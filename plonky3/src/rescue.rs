//! Native Rescue-Prime (Rp64_256) over Plonky3's Goldilocks, bit-compatible with the live chain.
//!
//! The live chain commits notes as `C = Rescue(value, blinding)` using Winterfell's Rp64_256. To
//! reuse those commitments on the Plonky3 stack, this reproduces the exact permutation (same MDS,
//! ARK schedule, S-box exponents, sponge init) over `p3_goldilocks::Goldilocks`. A cross-check test
//! asserts the digest equals Winterfell's `hash_elements`.

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

use crate::constants::{ARK1, ARK2, CAPACITY_INIT, INV_ALPHA, MDS, NUM_ROUNDS, STATE_WIDTH};

#[inline]
fn fe(x: u64) -> Goldilocks {
    Goldilocks::from_u64(x)
}

/// MDS matrix-vector product over Goldilocks.
fn mds_mul(state: &[Goldilocks; STATE_WIDTH]) -> [Goldilocks; STATE_WIDTH] {
    let mut out = [Goldilocks::ZERO; STATE_WIDTH];
    for (i, oi) in out.iter_mut().enumerate() {
        let mut acc = Goldilocks::ZERO;
        for (j, sj) in state.iter().enumerate() {
            acc += *sj * fe(MDS[i][j]);
        }
        *oi = acc;
    }
    out
}

/// One full Rescue round: forward S-box (x^7), MDS, +ARK1, inverse S-box (x^(1/7)), MDS, +ARK2.
pub fn apply_round(state: &mut [Goldilocks; STATE_WIDTH], r: usize) {
    for s in state.iter_mut() {
        *s = s.exp_u64(7);
    }
    *state = mds_mul(state);
    for (i, s) in state.iter_mut().enumerate() {
        *s += fe(ARK1[r][i]);
    }
    for s in state.iter_mut() {
        *s = s.exp_u64(INV_ALPHA);
    }
    *state = mds_mul(state);
    for (i, s) in state.iter_mut().enumerate() {
        *s += fe(ARK2[r][i]);
    }
}

/// Advance `state` by one Rescue round and ALSO return the inverse-S-box output `s`
/// (s = (MDS·cur^7 + ARK1)^(1/7)), the low-degree intermediate the AIR commits to so the round
/// constants are never nested inside a power: `s^7 = MDS·cur^7 + ARK1` and `next = MDS·s + ARK2`.
pub fn round_intermediate(state: &mut [Goldilocks; STATE_WIDTH], r: usize) -> [Goldilocks; STATE_WIDTH] {
    // first half: y = MDS·(cur^7) + ARK1
    let mut y = *state;
    for x in y.iter_mut() { *x = x.exp_u64(7); }
    y = mds_mul(&y);
    for (i, x) in y.iter_mut().enumerate() { *x += fe(ARK1[r][i]); }
    // inverse S-box: s = y^(1/7)
    let mut s = y;
    for x in s.iter_mut() { *x = x.exp_u64(INV_ALPHA); }
    // second half: next = MDS·s + ARK2
    let mut nxt = mds_mul(&s);
    for (i, x) in nxt.iter_mut().enumerate() { *x += fe(ARK2[r][i]); }
    *state = nxt;
    s
}

/// Sponge init matching Winterfell `hash_elements([value, blinding])`:
/// capacity cell 0 = element count (2), value at rate cell 4, blinding at rate cell 5, rest zero.
pub fn init_state(value: u64, blinding: u64) -> [Goldilocks; STATE_WIDTH] {
    let mut s = [Goldilocks::ZERO; STATE_WIDTH];
    s[0] = fe(CAPACITY_INIT);
    s[4] = fe(value);
    s[5] = fe(blinding);
    s
}

/// The 4-element Rescue digest (state cells 4..8 after the permutation).
pub fn hash2(value: u64, blinding: u64) -> [Goldilocks; 4] {
    let mut s = init_state(value, blinding);
    for r in 0..NUM_ROUNDS {
        apply_round(&mut s, r);
    }
    [s[4], s[5], s[6], s[7]]
}

/// The 32-byte commitment (4 x u64 little-endian), matching the live chain's encoding.
pub fn commit_bytes(value: u64, blinding: u64) -> [u8; 32] {
    let d = hash2(value, blinding);
    let mut b = [0u8; 32];
    for k in 0..4 {
        b[k * 8..k * 8 + 8].copy_from_slice(&d[k].as_canonical_u64().to_le_bytes());
    }
    b
}
