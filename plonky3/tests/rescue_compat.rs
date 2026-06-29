// Cross-check: the p3 Rescue digest MUST equal the live chain's Winterfell Rp64_256 hash.
use qbc_pq_confidential_p3::rescue;
use winterfell::crypto::{hashers::Rp64_256, ElementHasher};
use winterfell::math::{fields::f64::BaseElement, StarkField};

fn winter_commit(v: u64, b: u64) -> [u64; 4] {
    let d = Rp64_256::hash_elements(&[BaseElement::new(v), BaseElement::new(b)]);
    let e = d.as_elements();
    [e[0].as_int(), e[1].as_int(), e[2].as_int(), e[3].as_int()]
}

#[test]
fn p3_rescue_matches_live_chain() {
    // Goldilocks modulus p = 2^64 - 2^32 + 1. Both p3 (from_u64) and Winterfell (BaseElement::new)
    // reduce their inputs mod p, so even u64 values above p must produce identical digests; these
    // vectors cross-check that the reduction and the permutation agree across the full input range.
    const P: u64 = 0xFFFF_FFFF_0000_0001;
    let cases = [
        (0u64, 0u64), (1, 2), (1_527_000_000, 0xDEAD_BEEF), (42, 7),
        (u32::MAX as u64, 999), (100_000_000, 314159),
        (0, 1), (1, 0), (u64::MAX, 0), (0, u64::MAX), (u64::MAX, u64::MAX),
        (P - 1, 0), (P, 0), (P + 1, 0), (0, P - 1), (0, P), (0, P + 1), (P - 1, P - 1),
        (1u64 << 62, 0), ((1u64 << 62) - 1, 1), (1u64 << 63, 12345),
        (1 << 32, 1 << 16), (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555),
        (0xFFFF_FFFF, 0xFFFF_FFFF_0000_0000), (123_456_789, 987_654_321),
    ];
    for (v, b) in cases {
        let p3 = rescue::hash2(v, b);
        let p3u = [p3[0], p3[1], p3[2], p3[3]].map(|x| {
            use p3_field::PrimeField64; x.as_canonical_u64()
        });
        let wf = winter_commit(v, b);
        assert_eq!(p3u, wf, "MISMATCH for (v={v}, b={b}): p3={p3u:?} winterfell={wf:?}");
    }
    println!("p3 Rescue digest == live-chain Winterfell hash for all cases");
}
