//! Zero-knowledge commitment opening to a PUBLIC value — the shield/unshield bridge unit.
//!
//! Proves `C = Rescue(value, blinding)` for a PUBLIC commitment `C` and a PUBLIC `value`, with
//! the `blinding` SECRET and statistically hidden. This is the on/off-ramp counterpart to
//! [`crate::zk_commit`] (which keeps the value hidden): here the value is revealed on purpose
//! (it equals the plaintext UTXO amount being shielded or unshielded), so the chain can enforce
//! no inflation — exactly `value` burned equals `value` minted — while the note's blinding, and
//! therefore the note's future unlinkability, stays secret.
//!
//! Mechanically it is [`crate::zk_commit`] with one extra boundary: the value cell at row 0 is
//! asserted equal to the public `value`. The Rescue permutation, the continuous masking tail, and
//! the ZK argument are identical, so a note minted here is bit-for-bit the same Rescue commitment
//! that `confidential_transfer_v3` consumes.

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
use crate::zk_commit::{rand_felt, zero_round, BLIND_CELL};

mod v {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

// ───────────────────────── public inputs ─────────────────────────

#[derive(Clone)]
pub struct ZkOpenPublicInputs {
    pub commitment: [BaseElement; DIGEST_SIZE],
    pub value: BaseElement,
    /// AUDIT FIX (2026-06-29): a 32-byte context bound into the proof via Fiat-Shamir (it is in
    /// `to_elements`, so it seeds the verifier's random coin — a proof is INVALID for any other
    /// context). unshield_v3 sets this to the destination address, so a relayer or mempool
    /// front-runner cannot re-point a captured (commitment, value, proof) to their own address.
    /// shield_v3 sets a fixed domain sentinel. Packed as 8 × u32 (4 bytes each) → injective over
    /// 32 bytes, no field-modulus wraparound (every chunk < 2^32 < p).
    pub context: [BaseElement; 8],
}

/// Pack a 32-byte context (e.g. a destination address) into 8 field elements (4 bytes each).
/// Injective: distinct 32-byte values map to distinct element tuples (each chunk < 2^32 < p).
pub fn pack_context(bytes: &[u8; 32]) -> [BaseElement; 8] {
    let mut out = [BaseElement::new(0); 8];
    for i in 0..8 {
        let mut le = [0u8; 4];
        le.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
        out[i] = BaseElement::new(u32::from_le_bytes(le) as u64);
    }
    out
}

/// Domain sentinel for shield_v3 contexts (distinguishes a shield opening proof from an unshield
/// opening proof, and is never a valid destination — unshield rejects an all-zero destination).
pub const SHIELD_CONTEXT: [u8; 32] = [0u8; 32];

impl ToElements<BaseElement> for ZkOpenPublicInputs {
    fn to_elements(&self) -> v::Vec<BaseElement> {
        let mut e = self.commitment.to_vec();
        e.push(self.value);
        e.extend_from_slice(&self.context);
        e
    }
}

// ───────────────────────── the AIR ─────────────────────────

pub struct ZkOpenAir {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; DIGEST_SIZE],
    value: BaseElement,
}

impl Air for ZkOpenAir {
    type BaseField = BaseElement;
    type PublicInputs = ZkOpenPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = v::vec![TransitionConstraintDegree::new(7); STATE_WIDTH];
        // boundaries: row0 capacity+padding (10) + value-at-row0 (1) + digest (4) = 15
        let context = AirContext::new(trace_info, degrees, 15, options)
            .set_num_transition_exemptions(EXEMPT);
        ZkOpenAir { context, commitment: pub_inputs.commitment, value: pub_inputs.value }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// Period-8 round constants (identical to zk_commit): indices 0..6 are the real Rescue ARK,
    /// index 7 is a zero-constant round that keeps the permutation running across the mask budget.
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
        let mut a = v::Vec::with_capacity(15);
        a.push(Assertion::single(0, 0, BaseElement::new(CAPACITY_INIT)));
        for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
            a.push(Assertion::single(c, 0, BaseElement::ZERO));
        }
        // value cell at row 0 == the PUBLIC value (this is the only addition over zk_commit).
        a.push(Assertion::single(VALUE_CELL, 0, self.value));
        for k in 0..DIGEST_SIZE {
            a.push(Assertion::single(VALUE_CELL + k, DIGEST_ROW, self.commitment[k]));
        }
        a
    }
}

// ───────────────────────── prover (std only) ─────────────────────────

#[cfg(feature = "prover")]
pub struct ZkOpenProver {
    options: ProofOptions,
    context: [BaseElement; 8],
}

#[cfg(feature = "prover")]
impl ZkOpenProver {
    pub fn new(options: ProofOptions, context: [BaseElement; 8]) -> Self {
        Self { options, context }
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
        for row in (last_src + 2)..TRACE_LEN {
            for c in 0..STATE_WIDTH {
                cols[c][row] = rand_felt();
            }
        }
        TraceTable::init(cols)
    }
}

#[cfg(feature = "prover")]
impl Prover for ZkOpenProver {
    type BaseField = BaseElement;
    type Air = ZkOpenAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ZkOpenPublicInputs {
        let mut c = [BaseElement::ZERO; DIGEST_SIZE];
        for k in 0..DIGEST_SIZE {
            c[k] = trace.get(VALUE_CELL + k, DIGEST_ROW);
        }
        ZkOpenPublicInputs { commitment: c, value: trace.get(VALUE_CELL, 0), context: self.context }
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

/// Prove that the Rescue commitment of `(value, blinding)` opens to the PUBLIC `value`, bound to
/// `context` (a 32-byte domain/destination). Returns the commitment + proof.
#[cfg(feature = "prover")]
pub fn prove_zk_open(
    value: u64,
    blinding: u64,
    context: &[u8; 32],
) -> ([BaseElement; DIGEST_SIZE], v::Vec<u8>) {
    let prover = ZkOpenProver::new(crate::proof_options(), pack_context(context));
    let trace = prover.build_trace(value, blinding);
    let c = prover.get_pub_inputs(&trace).commitment;
    let proof = prover.prove(trace).expect("zk-open prove");
    (c, proof.to_bytes())
}

/// Prover convenience returning the 32-byte commitment (4×u64-LE) + proof — no winterfell types
/// leak to CLI / browser-wasm callers. `context` binds the proof (unshield: the dest; shield:
/// `SHIELD_CONTEXT`).
#[cfg(feature = "prover")]
pub fn prove_zk_open_bytes(value: u64, blinding: u64, context: &[u8; 32]) -> ([u8; 32], v::Vec<u8>) {
    let (c, proof) = prove_zk_open(value, blinding, context);
    let mut b = [0u8; 32];
    for k in 0..DIGEST_SIZE {
        b[k * 8..k * 8 + 8].copy_from_slice(&c[k].as_int().to_le_bytes());
    }
    (b, proof)
}

pub fn verify_zk_open(
    commitment: &[BaseElement; DIGEST_SIZE],
    value: u64,
    context: &[u8; 32],
    proof_bytes: &[u8],
) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pubs = ZkOpenPublicInputs {
        commitment: *commitment,
        value: BaseElement::new(value),
        context: pack_context(context),
    };
    let min = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<
        ZkOpenAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pubs, &min)
    .is_ok()
}

/// Runtime-facing raw-bytes verify (no winterfell types leak). 32-byte commitment (4×u64-LE) and
/// 32-byte `context` (unshield binds the destination here; shield uses `SHIELD_CONTEXT`).
pub fn verify_open_bundle(
    commitment: &[u8; 32],
    value: u64,
    context: &[u8; 32],
    proof_bytes: &[u8],
) -> bool {
    let mut d = [BaseElement::new(0); DIGEST_SIZE];
    for k in 0..DIGEST_SIZE {
        let mut le = [0u8; 8];
        le.copy_from_slice(&commitment[k * 8..k * 8 + 8]);
        d[k] = BaseElement::new(u64::from_le_bytes(le));
    }
    verify_zk_open(&d, value, context, proof_bytes)
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::zk_commit::commit;

    const CTX: [u8; 32] = [7u8; 32];

    #[test]
    fn open_verifies_and_matches_native_hash() {
        let (c, p) = prove_zk_open(1_527_000_000, 0xDEAD_BEEF, &CTX);
        assert_eq!(c, commit(1_527_000_000, 0xDEAD_BEEF));
        assert!(verify_zk_open(&c, 1_527_000_000, &CTX, &p));
    }

    #[test]
    fn wrong_public_value_rejected() {
        // The proof binds the commitment to a SPECIFIC public value: claiming a different value
        // for the same commitment must fail (this is the no-inflation guarantee).
        let (c, p) = prove_zk_open(100, 7, &CTX);
        assert!(verify_zk_open(&c, 100, &CTX, &p));
        assert!(!verify_zk_open(&c, 101, &CTX, &p), "wrong public value must be rejected");
        assert!(!verify_zk_open(&c, 99, &CTX, &p), "wrong public value must be rejected");
    }

    #[test]
    fn wrong_context_rejected() {
        // AUDIT REGRESSION (unshield dest-binding): a proof bound to one context must NOT verify
        // under another. This is what stops a relayer/front-runner re-pointing an unshield to a
        // different destination.
        let (c, p) = prove_zk_open(500, 9, &[0xAAu8; 32]);
        assert!(verify_zk_open(&c, 500, &[0xAAu8; 32], &p), "correct context verifies");
        assert!(!verify_zk_open(&c, 500, &[0xBBu8; 32], &p), "different context (dest) must be rejected");
        // a single-byte change in the destination must invalidate the proof
        let mut ctx2 = [0xAAu8; 32];
        ctx2[31] ^= 0x01;
        assert!(!verify_zk_open(&c, 500, &ctx2, &p), "one-byte dest change must be rejected");
    }

    #[test]
    fn binds_to_commitment() {
        let (c, p) = prove_zk_open(50, 9, &CTX);
        assert!(verify_zk_open(&c, 50, &CTX, &p));
        let mut c2 = c;
        c2[0] += BaseElement::ONE;
        assert!(!verify_zk_open(&c2, 50, &CTX, &p));
    }

    #[test]
    fn proofs_are_randomized() {
        let (c1, p1) = prove_zk_open(42, 7, &CTX);
        let (c2, p2) = prove_zk_open(42, 7, &CTX);
        assert_eq!(c1, c2);
        assert_ne!(p1, p2, "blinding must stay hidden → proofs randomized");
        assert!(verify_zk_open(&c1, 42, &CTX, &p1) && verify_zk_open(&c2, 42, &CTX, &p2));
    }

    #[test]
    fn tampered_rejected() {
        let (c, mut p) = prove_zk_open(55, 66, &CTX);
        let m = p.len() / 2;
        p[m] ^= 0xff;
        assert!(!verify_zk_open(&c, 55, &CTX, &p));
    }

    #[test]
    fn bytes_roundtrip_matches() {
        let (c, p) = prove_zk_open(777, 12345, &CTX);
        let (cb, pb) = prove_zk_open_bytes(777, 12345, &CTX);
        let mut b = [0u8; 32];
        for k in 0..DIGEST_SIZE {
            b[k * 8..k * 8 + 8].copy_from_slice(&c[k].as_int().to_le_bytes());
        }
        assert_eq!(cb, b);
        assert!(verify_open_bundle(&cb, 777, &CTX, &pb));
        assert!(verify_open_bundle(&cb, 777, &CTX, &p));
    }
}
