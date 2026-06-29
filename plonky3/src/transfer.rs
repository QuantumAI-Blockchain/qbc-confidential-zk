//! Full 2-in / 2-out confidential transfer AIR on Plonky3 (LOW-DEGREE), native FRI zero-knowledge.
//!
//! Proves, with amounts hidden: each of the 4 note commitments opens; balance
//! v_in0 + v_in1 = v_out0 + v_out1 + fee; and each OUTPUT value < 2^62.
//!
//! Low-degree Rescue: per block, each row holds 12 state cells + 12 intermediate inverse-S-box
//! cells `s`, so a round is two degree-7 constraints (s^7 = MDS·cur^7 + ARK1 ; next = MDS·s + ARK2)
//! with the round constants added, never nested in a power. Constraint degree stays 7 (FRI blowup 8).
//!
//! Layout (8 rows):
//!   block b: state [b*24 .. b*24+12), s [b*24+12 .. b*24+24)   (b=0,1 inputs; 2,3 outputs)
//!   col 96+b : vheld[b] (constant = note value);  col 100+b : d[b] = state4 - vheld (d[0]=0)
//!   col 104 + j*62 + i : bit i of output j's value (range gadget, single row)
//! Public inputs: in_commitments[2][4], out_commitments[2][4], fee  (17).

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
const N_BLOCKS: usize = 4;
const BLOCK: usize = 2 * STATE_WIDTH; // 24 (state + s)
pub const RANGE_BITS: usize = 62;
const VHELD_BASE: usize = N_BLOCKS * BLOCK; // 96
const D_BASE: usize = VHELD_BASE + N_BLOCKS; // 100
const BIT_BASE: usize = D_BASE + N_BLOCKS; // 104
const WIDTH: usize = BIT_BASE + 2 * RANGE_BITS; // 228
const N_PUBLIC: usize = 4 * DIGEST + 1; // 17

#[inline]
fn st(b: usize) -> usize { b * BLOCK }
#[inline]
fn sb(b: usize) -> usize { b * BLOCK + STATE_WIDTH } // intermediate-s base for block b
#[inline]
fn vheld(b: usize) -> usize { VHELD_BASE + b }
#[inline]
fn dcol(b: usize) -> usize { D_BASE + b }
#[inline]
fn bit(j: usize, i: usize) -> usize { BIT_BASE + j * RANGE_BITS + i }

pub struct TransferAir;

impl<F: PrimeCharacteristicRing> BaseAir<F> for TransferAir {
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

impl<AB: AirBuilder> Air<AB> for TransferAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();
        let per = builder.periodic_values().to_vec();
        let pis = builder.public_values().to_vec();
        let cst = |c: u64| AB::Expr::from(AB::F::from_u64(c));
        let ark1: Vec<AB::Expr> = (0..STATE_WIDTH).map(|k| per[k].into()).collect();
        let ark2: Vec<AB::Expr> = (0..STATE_WIDTH).map(|k| per[STATE_WIDTH + k].into()).collect();

        for b in 0..N_BLOCKS {
            // first-row sponge init + d[0]=0
            {
                let mut fr = builder.when_first_row();
                fr.assert_eq(cur[st(b)].into(), cst(CAPACITY_INIT));
                for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
                    fr.assert_zero(cur[st(b) + c].into());
                }
                fr.assert_zero(cur[dcol(b)].into());
            }
            // Rescue round (degree 7): C1 s^7 = MDS·cur^7 + ARK1 ; C2 next = MDS·s + ARK2
            let cp7: Vec<AB::Expr> = (0..STATE_WIDTH).map(|i| pow7::<AB::Expr>(cur[st(b) + i].into())).collect();
            for i in 0..STATE_WIDTH {
                let mut mds_cur = AB::Expr::ZERO;
                let mut mds_s = AB::Expr::ZERO;
                for j in 0..STATE_WIDTH {
                    mds_cur = mds_cur + cp7[j].clone() * cst(MDS[i][j]);
                    mds_s = mds_s + AB::Expr::from(cur[sb(b) + j]) * cst(MDS[i][j]);
                }
                builder
                    .when_transition()
                    .assert_zero(pow7::<AB::Expr>(cur[sb(b) + i].into()) - (mds_cur + ark1[i].clone()));
                builder
                    .when_transition()
                    .assert_zero(AB::Expr::from(next[st(b) + i]) - (mds_s + ark2[i].clone()));
            }
            // vheld constant + d link
            builder.when_transition().assert_zero(AB::Expr::from(next[vheld(b)]) - AB::Expr::from(cur[vheld(b)]));
            builder.assert_zero(AB::Expr::from(cur[dcol(b)]) - (AB::Expr::from(cur[st(b) + 4]) - AB::Expr::from(cur[vheld(b)])));
            // digest == commitment (last row)
            {
                let mut lr = builder.when_last_row();
                for k in 0..DIGEST {
                    lr.assert_eq(cur[st(b) + 4 + k].into(), pis[b * DIGEST + k].into());
                }
            }
        }

        // balance (first row): vin0 + vin1 - vout0 - vout1 - fee == 0
        {
            let fee = pis[4 * DIGEST].into();
            let mut fr = builder.when_first_row();
            let bal = AB::Expr::from(cur[vheld(0)]) + AB::Expr::from(cur[vheld(1)])
                - AB::Expr::from(cur[vheld(2)]) - AB::Expr::from(cur[vheld(3)]) - fee;
            fr.assert_zero(bal);
        }

        // range (first row): each output value = Σ 2^i · bit_i, bits binary, < 2^62
        for j in 0..2 {
            let out_block = 2 + j;
            let mut fr = builder.when_first_row();
            let mut acc = AB::Expr::ZERO;
            for i in 0..RANGE_BITS {
                let bcol = cur[bit(j, i)].into();
                fr.assert_zero(bcol.clone() * (bcol.clone() - AB::Expr::ONE));
                acc = acc + bcol * cst(1u64 << i);
            }
            fr.assert_eq(AB::Expr::from(cur[vheld(out_block)]), acc);
        }
    }
}

/// Build the transfer trace + public inputs. in/out notes are (value, blinding).
#[cfg(feature = "prover")]
pub fn build_trace(
    in_notes: &[(u64, u64); 2],
    out_notes: &[(u64, u64); 2],
    fee: u64,
) -> Option<(RowMajorMatrix<Val>, Vec<Val>)> {
    let si: u128 = in_notes.iter().map(|n| n.0 as u128).sum();
    let so: u128 = out_notes.iter().map(|n| n.0 as u128).sum();
    if si != so + fee as u128 {
        return None;
    }
    if out_notes.iter().any(|n| n.0 >= (1u64 << RANGE_BITS)) {
        return None;
    }

    let notes = [in_notes[0], in_notes[1], out_notes[0], out_notes[1]];
    let mut cols = vec![Val::ZERO; TRACE_ROWS * WIDTH];
    let mut digests = [[Val::ZERO; DIGEST]; N_BLOCKS];

    for (b, &(v, bl)) in notes.iter().enumerate() {
        let mut state = rescue::init_state(v, bl);
        let vfe = Val::from_u64(v);
        for r in 0..NUM_ROUNDS {
            for c in 0..STATE_WIDTH {
                cols[r * WIDTH + st(b) + c] = state[c];
            }
            let s = rescue::round_intermediate(&mut state, r);
            for c in 0..STATE_WIDTH {
                cols[r * WIDTH + sb(b) + c] = s[c];
            }
        }
        for c in 0..STATE_WIDTH {
            cols[NUM_ROUNDS * WIDTH + st(b) + c] = state[c];
        }
        digests[b] = [state[4], state[5], state[6], state[7]];
        // vheld constant + d = state4 - vheld, all rows
        for row in 0..TRACE_ROWS {
            cols[row * WIDTH + vheld(b)] = vfe;
            cols[row * WIDTH + dcol(b)] = cols[row * WIDTH + st(b) + 4] - vfe;
        }
    }
    // range bits for the 2 outputs (row 0)
    for j in 0..2 {
        let v = out_notes[j].0;
        for i in 0..RANGE_BITS {
            cols[bit(j, i)] = Val::from_u64((v >> i) & 1);
        }
    }

    let mut pis = Vec::with_capacity(N_PUBLIC);
    for b in 0..N_BLOCKS {
        for k in 0..DIGEST {
            pis.push(digests[b][k]);
        }
    }
    pis.push(Val::from_u64(fee));
    Some((RowMajorMatrix::new(cols, WIDTH), pis))
}

/// commitment bytes for a note (matches the live chain).
#[cfg(feature = "prover")]
pub fn commit_bytes(v: u64, b: u64) -> [u8; 32] {
    rescue::commit_bytes(v, b)
}

/// Prove a transfer; returns (in_commitments[2], out_commitments[2], proof).
#[cfg(feature = "prover")]
pub fn prove_transfer(
    in_notes: &[(u64, u64); 2],
    out_notes: &[(u64, u64); 2],
    fee: u64,
) -> Option<([[u8; 32]; 2], [[u8; 32]; 2], Vec<u8>)> {
    let config = zk_config();
    let (trace, pis) = build_trace(in_notes, out_notes, fee)?;
    let proof = prove(&config, &TransferAir, trace, &pis);
    let to_b = |off: usize| -> [u8; 32] {
        let mut b = [0u8; 32];
        for k in 0..DIGEST {
            b[k * 8..k * 8 + 8].copy_from_slice(&pis[off + k].as_canonical_u64().to_le_bytes());
        }
        b
    };
    Some((
        [to_b(0), to_b(DIGEST)],
        [to_b(2 * DIGEST), to_b(3 * DIGEST)],
        postcard::to_allocvec(&proof).ok()?,
    ))
}

/// Verify a transfer bundle: commitments (32 bytes each) + fee + proof.
pub fn verify_transfer(
    in_c: &[[u8; 32]; 2],
    out_c: &[[u8; 32]; 2],
    fee: u64,
    proof_bytes: &[u8],
) -> bool {
    if fee >= (1u64 << RANGE_BITS) {
        return false; // audit: bound fee so the field balance cannot wrap
    }
    let config = zk_config_verify();
    let proof = match postcard::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let to_fe = |c: &[u8; 32]| -> Vec<Val> {
        (0..DIGEST)
            .map(|k| {
                let mut le = [0u8; 8];
                le.copy_from_slice(&c[k * 8..k * 8 + 8]);
                Val::from_u64(u64::from_le_bytes(le))
            })
            .collect()
    };
    let mut pis: Vec<Val> = Vec::with_capacity(N_PUBLIC);
    pis.extend(to_fe(&in_c[0]));
    pis.extend(to_fe(&in_c[1]));
    pis.extend(to_fe(&out_c[0]));
    pis.extend(to_fe(&out_c[1]));
    pis.push(Val::from_u64(fee));
    verify(&config, &TransferAir, &proof, &pis).is_ok()
}
