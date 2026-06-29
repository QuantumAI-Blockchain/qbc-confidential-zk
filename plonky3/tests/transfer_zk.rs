use qbc_pq_confidential_p3::transfer;

#[test]
fn p3_zk_transfer_roundtrip_binding_and_balance() {
    let ins = [(10u64, 111u64), (7u64, 222u64)];
    let outs = [(12u64, 333u64), (4u64, 444u64)]; // 17 = 16 + fee 1
    let (in_c, out_c, proof) = transfer::prove_transfer(&ins, &outs, 1).expect("balanced+in range");
    // commitments match the live chain
    assert_eq!(in_c[0], transfer::commit_bytes(10, 111));
    assert_eq!(out_c[1], transfer::commit_bytes(4, 444));
    // valid verifies
    assert!(transfer::verify_transfer(&in_c, &out_c, 1, &proof), "valid ZK transfer must verify");
    // forged fee rejected
    assert!(!transfer::verify_transfer(&in_c, &out_c, 2, &proof), "forged fee must be rejected");
    // forged commitment rejected
    let mut bad = out_c.clone(); bad[0][0] ^= 1;
    assert!(!transfer::verify_transfer(&in_c, &bad, 1, &proof), "forged commitment must be rejected");
    println!("p3 ZK transfer: verify OK, commitments match live chain, balance+binding hold. proof_bytes={}", proof.len());
}

#[test]
fn p3_zk_transfer_unbalanced_and_out_of_range_unprovable() {
    // unbalanced (honest prover refuses)
    assert!(transfer::prove_transfer(&[(10,1),(7,2)], &[(12,3),(6,4)], 1).is_none(), "unbalanced");
    // out of range output
    assert!(transfer::prove_transfer(&[((1u64<<62),1),(0,2)], &[((1u64<<62),3),(0,4)], 0).is_none(), "out of range");
}

#[test]
fn p3_zk_transfer_proofs_are_randomized() {
    let ins = [(8u64, 5u64), (2u64, 6u64)];
    let outs = [(6u64, 7u64), (4u64, 8u64)];
    let (_i1,_o1,p1) = transfer::prove_transfer(&ins, &outs, 0).unwrap();
    let (_i2,_o2,p2) = transfer::prove_transfer(&ins, &outs, 0).unwrap();
    assert_ne!(p1, p2, "ZK: two transfer proofs of the same statement must differ");
    println!("p3 ZK transfer randomization confirmed");
}

#[test]
fn p3_zk_transfer_tampered_rejected() {
    let ins = [(5u64,1u64),(5u64,2u64)];
    let outs = [(6u64,3u64),(3u64,4u64)];
    let (i,o,mut p) = transfer::prove_transfer(&ins, &outs, 1).unwrap();
    let m = p.len()/2; p[m] ^= 0xff;
    assert!(!transfer::verify_transfer(&i, &o, 1, &p), "tampered proof must be rejected");
}
