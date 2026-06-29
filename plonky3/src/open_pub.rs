//! Public-value opening AIR on Plonky3 (LOW-DEGREE), shield / unshield ramp, native FRI ZK.
//!
//! Proves C = Rescue(value, blinding) with `value` PUBLIC and the blinding hidden, bound to a
//! 32-byte `context` (unshield: the destination; shield: a sentinel). Same two-degree-7-constraint
//! Rescue round as `opening` (intermediate `s` columns), plus a first-row boundary value == public.

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
const WIDTH: usize = 2 * STATE_WIDTH;
const CTX_ELEMS: usize = 8;
const N_PUBLIC: usize = DIGEST + 1 + CTX_ELEMS; // commitment(4) + value(1) + context(8) = 13

/// All-zero shield-context sentinel (matches the deployed `SHIELD_CONTEXT`).
pub const SHIELD_CONTEXT: [u8; 32] = [0u8; 32];

fn pack_ctx(ctx: &[u8; 32]) -> [Val; CTX_ELEMS] {
    let mut out = [Val::ZERO; CTX_ELEMS];
    for i in 0..CTX_ELEMS {
        let mut le = [0u8; 4];
        le.copy_from_slice(&ctx[i * 4..i * 4 + 4]);
        out[i] = Val::from_u64(u32::from_le_bytes(le) as u64);
    }
    out
}

pub struct PubOpenAir;

impl<F: PrimeCharacteristicRing> BaseAir<F> for PubOpenAir {
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
        N_PUBLIC
    }
}

#[inline]
fn pow7<E: PrimeCharacteristicRing + Clone>(x: E) -> E {
    let x2 = x.clone() * x.clone();
    let x3 = x2 * x.clone();
    let x6 = x3.clone() * x3;
    x6 * x
}

impl<AB: AirBuilder> Air<AB> for PubOpenAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let per = builder.periodic_values().to_vec();
        let pis = builder.public_values().to_vec();
        let cst = |c: u64| AB::Expr::from(AB::F::from_u64(c));
        let ark1: Vec<AB::Expr> = (0..STATE_WIDTH).map(|k| per[k].into()).collect();
        let ark2: Vec<AB::Expr> = (0..STATE_WIDTH).map(|k| per[STATE_WIDTH + k].into()).collect();

        // first row: sponge init + value cell == PUBLIC value
        {
            let mut fr = builder.when_first_row();
            fr.assert_eq(cur[0].into(), cst(CAPACITY_INIT));
            for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
                fr.assert_zero(cur[c].into());
            }
            fr.assert_eq(cur[4].into(), pis[DIGEST].into()); // value is public
        }

        // transition (degree 7)
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
fn build_trace(value: u64, blinding: u64, ctx: &[u8; 32]) -> (RowMajorMatrix<Val>, Vec<Val>) {
    let mut state = rescue::init_state(value, blinding);
    let mut cols = vec![Val::ZERO; TRACE_ROWS * WIDTH];
    for r in 0..NUM_ROUNDS {
        for c in 0..STATE_WIDTH {
            cols[r * WIDTH + c] = state[c];
        }
        let s = rescue::round_intermediate(&mut state, r);
        for c in 0..STATE_WIDTH {
            cols[r * WIDTH + STATE_WIDTH + c] = s[c];
        }
    }
    for c in 0..STATE_WIDTH {
        cols[NUM_ROUNDS * WIDTH + c] = state[c];
    }
    let mut pis = vec![state[4], state[5], state[6], state[7], Val::from_u64(value)];
    pis.extend_from_slice(&pack_ctx(ctx));
    (RowMajorMatrix::new(cols, WIDTH), pis)
}

/// Prove a public-value opening bound to `context`. Returns (commitment32, proof).
#[cfg(feature = "prover")]
pub fn prove_open_pub(value: u64, blinding: u64, ctx: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let config = zk_config();
    let (trace, pis) = build_trace(value, blinding, ctx);
    let proof = prove(&config, &PubOpenAir, trace, &pis);
    let mut c = [0u8; 32];
    for k in 0..DIGEST {
        c[k * 8..k * 8 + 8].copy_from_slice(&pis[k].as_canonical_u64().to_le_bytes());
    }
    (c, postcard::to_allocvec(&proof).expect("ser"))
}

/// Verify a public-value opening: commitment opens to the PUBLIC value, bound to `context`.
pub fn verify_open_pub(commitment: &[u8; 32], value: u64, ctx: &[u8; 32], proof_bytes: &[u8]) -> bool {
    let config = zk_config_verify();
    let proof = match postcard::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut pis: Vec<Val> = (0..DIGEST)
        .map(|k| {
            let mut le = [0u8; 8];
            le.copy_from_slice(&commitment[k * 8..k * 8 + 8]);
            Val::from_u64(u64::from_le_bytes(le))
        })
        .collect();
    pis.push(Val::from_u64(value));
    pis.extend_from_slice(&pack_ctx(ctx));
    verify(&config, &PubOpenAir, &proof, &pis).is_ok()
}
