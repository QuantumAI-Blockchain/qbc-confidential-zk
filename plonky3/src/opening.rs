//! Opening AIR on Plonky3 (LOW-DEGREE): proves knowledge of (value, blinding) with a PUBLIC
//! commitment C = Rescue(value, blinding), under the native zero-knowledge `HidingFriPcs`.
//!
//! Each row carries the 12 Rescue state cells plus 12 intermediate inverse-S-box cells `s`, so a
//! round is two degree-7 constraints with the round constants ADDED (never nested in a power):
//!   C1:  s^7   == MDS·cur^7 + ARK1
//!   C2:  next  == MDS·s     + ARK2
//! This keeps the constraint degree at 7 (FRI blowup 8) instead of ~49, shrinking the proof.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
#[cfg(feature = "prover")]
use p3_field::PrimeField64;
#[cfg(feature = "prover")]
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::verify;
#[cfg(feature = "prover")]
use p3_uni_stark::prove;

use crate::config::zk_config_verify;
#[cfg(feature = "prover")]
use crate::config::zk_config;
use crate::config::Val;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use crate::constants::{ARK1, ARK2, CAPACITY_INIT, MDS, NUM_ROUNDS, STATE_WIDTH};
#[cfg(feature = "prover")]
use crate::rescue;

const TRACE_ROWS: usize = 8;
const DIGEST: usize = 4;
const WIDTH: usize = 2 * STATE_WIDTH; // 12 state + 12 intermediate s

pub struct OpeningAir;

impl<F: PrimeCharacteristicRing> BaseAir<F> for OpeningAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_periodic_columns(&self) -> usize {
        2 * STATE_WIDTH
    }
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut cols = Vec::with_capacity(2 * STATE_WIDTH);
        for k in 0..STATE_WIDTH {
            let mut c = vec![F::ZERO; TRACE_ROWS];
            for r in 0..NUM_ROUNDS {
                c[r] = F::from_u64(ARK1[r][k]);
            }
            cols.push(c);
        }
        for k in 0..STATE_WIDTH {
            let mut c = vec![F::ZERO; TRACE_ROWS];
            for r in 0..NUM_ROUNDS {
                c[r] = F::from_u64(ARK2[r][k]);
            }
            cols.push(c);
        }
        cols
    }
    fn num_public_values(&self) -> usize {
        DIGEST
    }
}

#[inline]
fn pow7<E: PrimeCharacteristicRing + Clone>(x: E) -> E {
    let x2 = x.clone() * x.clone();
    let x3 = x2 * x.clone();
    let x6 = x3.clone() * x3;
    x6 * x
}

impl<AB: AirBuilder> Air<AB> for OpeningAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let per = builder.periodic_values().to_vec();
        let pis = builder.public_values().to_vec();
        let cst = |c: u64| AB::Expr::from(AB::F::from_u64(c));
        let ark1: Vec<AB::Expr> = (0..STATE_WIDTH).map(|k| per[k].into()).collect();
        let ark2: Vec<AB::Expr> = (0..STATE_WIDTH).map(|k| per[STATE_WIDTH + k].into()).collect();

        // first row: sponge init
        {
            let mut fr = builder.when_first_row();
            fr.assert_eq(cur[0].into(), cst(CAPACITY_INIT));
            for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
                fr.assert_zero(cur[c].into());
            }
        }

        // transition (degree 7): C1 s^7 = MDS·cur^7 + ARK1 ; C2 next = MDS·s + ARK2
        let cp7: Vec<AB::Expr> = (0..STATE_WIDTH).map(|i| pow7::<AB::Expr>(cur[i].into())).collect();
        for i in 0..STATE_WIDTH {
            let mut mds_cur = AB::Expr::ZERO;
            let mut mds_s = AB::Expr::ZERO;
            for j in 0..STATE_WIDTH {
                mds_cur = mds_cur + cp7[j].clone() * cst(MDS[i][j]);
                mds_s = mds_s + AB::Expr::from(cur[STATE_WIDTH + j]) * cst(MDS[i][j]);
            }
            builder
                .when_transition()
                .assert_zero(pow7::<AB::Expr>(cur[STATE_WIDTH + i].into()) - (mds_cur + ark1[i].clone()));
            builder
                .when_transition()
                .assert_zero(AB::Expr::from(next[i]) - (mds_s + ark2[i].clone()));
        }

        // last row: digest == commitment
        {
            let mut lr = builder.when_last_row();
            for k in 0..DIGEST {
                lr.assert_eq(cur[4 + k].into(), pis[k].into());
            }
        }
    }
}

#[cfg(feature = "prover")]
pub fn build_trace(value: u64, blinding: u64) -> (RowMajorMatrix<Val>, Vec<Val>) {
    let mut state = rescue::init_state(value, blinding);
    let mut cols = vec![Val::ZERO; TRACE_ROWS * WIDTH];
    for r in 0..NUM_ROUNDS {
        for c in 0..STATE_WIDTH {
            cols[r * WIDTH + c] = state[c];
        }
        let s = rescue::round_intermediate(&mut state, r); // advances state to row r+1
        for c in 0..STATE_WIDTH {
            cols[r * WIDTH + STATE_WIDTH + c] = s[c];
        }
    }
    for c in 0..STATE_WIDTH {
        cols[NUM_ROUNDS * WIDTH + c] = state[c];
    }
    let pis = vec![state[4], state[5], state[6], state[7]];
    (RowMajorMatrix::new(cols, WIDTH), pis)
}

#[cfg(feature = "prover")]
pub fn prove_open(value: u64, blinding: u64) -> ([u8; 32], Vec<u8>) {
    let config = zk_config();
    let (trace, pis) = build_trace(value, blinding);
    let proof = prove(&config, &OpeningAir, trace, &pis);
    let bytes = postcard_to_vec(&proof);
    let mut c = [0u8; 32];
    for k in 0..DIGEST {
        c[k * 8..k * 8 + 8].copy_from_slice(&pis[k].as_canonical_u64().to_le_bytes());
    }
    (c, bytes)
}

pub fn verify_open(commitment: &[u8; 32], proof_bytes: &[u8]) -> bool {
    let config = zk_config_verify();
    let proof = match postcard_from_slice(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    let pis: Vec<Val> = (0..DIGEST)
        .map(|k| {
            let mut le = [0u8; 8];
            le.copy_from_slice(&commitment[k * 8..k * 8 + 8]);
            Val::from_u64(u64::from_le_bytes(le))
        })
        .collect();
    verify(&config, &OpeningAir, &proof, &pis).is_ok()
}

type ProofT = p3_uni_stark::Proof<crate::config::ZkConfig>;
#[cfg(feature = "prover")]
fn postcard_to_vec(p: &ProofT) -> Vec<u8> {
    postcard::to_allocvec(p).expect("serialize proof")
}
fn postcard_from_slice(b: &[u8]) -> Option<ProofT> {
    postcard::from_bytes(b).ok()
}
