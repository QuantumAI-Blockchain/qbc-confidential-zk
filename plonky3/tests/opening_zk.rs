use qbc_pq_confidential_p3::{opening, rescue};

#[test]
fn p3_zk_opening_roundtrip_and_binding() {
    let (v, b) = (1_527_000_000u64, 0xDEAD_BEEFu64);
    let (commitment, proof) = opening::prove_open(v, b);
    // commitment equals the live-chain Rescue commitment
    assert_eq!(commitment, rescue::commit_bytes(v, b), "commitment must match live-chain hash");
    // valid proof verifies
    assert!(opening::verify_open(&commitment, &proof), "valid ZK opening must verify");
    // wrong commitment rejected (binding)
    let mut bad = commitment; bad[0] ^= 0x01;
    assert!(!opening::verify_open(&bad, &proof), "wrong commitment must be rejected");
    println!("p3 ZK opening: prove+verify OK, commitment matches live chain, binding holds. proof_bytes={}", proof.len());
}

#[test]
fn p3_zk_opening_proofs_are_randomized() {
    let (v, b) = (42u64, 7u64);
    let (c1, p1) = opening::prove_open(v, b);
    let (c2, p2) = opening::prove_open(v, b);
    assert_eq!(c1, c2, "same witness -> same commitment");
    assert_ne!(p1, p2, "ZK: two proofs of the same witness must differ (hiding PCS randomization)");
    assert!(opening::verify_open(&c1, &p1) && opening::verify_open(&c2, &p2));
    println!("p3 ZK randomization confirmed: proofs differ");
}
