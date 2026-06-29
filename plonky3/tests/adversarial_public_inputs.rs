// Soundness against PUBLIC-INPUT substitution: a valid Plonky3 transfer proof is bound to the exact
// statement it was generated for. Re-using it under ANY altered public input (a different input or
// output commitment, a different fee, swapped roles) must be rejected. This complements fuzz_verify
// (which mutates the proof bytes) by instead holding the proof fixed and perturbing the statement —
// the channel an attacker actually controls when relaying someone else's proof. (Reviewer M-2.)
use qbc_pq_confidential_p3::transfer;

fn xs(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

#[test]
fn valid_proof_rejected_under_any_altered_public_input() {
    let ins = [(10u64, 111u64), (7u64, 222u64)];
    let outs = [(12u64, 333u64), (4u64, 444u64)]; // 17 = 16 + fee 1
    let fee = 1u64;
    let (in_c, out_c, proof) = transfer::prove_transfer(&ins, &outs, fee).expect("valid");

    // baseline: the honest statement verifies.
    assert!(transfer::verify_transfer(&in_c, &out_c, fee, &proof), "honest statement must verify");

    let mut rejected = 0u64;
    let mut total = 0u64;
    let mut seed = 0xC0FF_EE12_3456_789Au64;

    // 1. flip every byte of every commitment, one at a time -> all must reject.
    for which in 0..4 {
        for byte in 0..32 {
            let mut ic = in_c;
            let mut oc = out_c;
            match which {
                0 => ic[0][byte] ^= 0xff,
                1 => ic[1][byte] ^= 0xff,
                2 => oc[0][byte] ^= 0xff,
                _ => oc[1][byte] ^= 0xff,
            }
            total += 1;
            if !transfer::verify_transfer(&ic, &oc, fee, &proof) { rejected += 1; }
        }
    }

    // 2. many random fees != the real fee -> all must reject.
    for _ in 0..200 {
        let f = xs(&mut seed);
        if f == fee { continue; }
        total += 1;
        if !transfer::verify_transfer(&in_c, &out_c, f, &proof) { rejected += 1; }
    }

    // 3. role swaps (inputs<->outputs, intra-side swaps) -> must reject (proof is position-bound).
    let swaps = [
        ([out_c[0], out_c[1]], [in_c[0], in_c[1]]),   // in<->out
        ([in_c[1], in_c[0]], out_c),                  // swap the two inputs
        (in_c, [out_c[1], out_c[0]]),                 // swap the two outputs
    ];
    for (ic, oc) in swaps {
        total += 1;
        if !transfer::verify_transfer(&ic, &oc, fee, &proof) { rejected += 1; }
    }

    // 4. random whole-commitment replacements -> must reject.
    for _ in 0..200 {
        let mut ic = in_c;
        let mut oc = out_c;
        let mut rnd = [0u8; 32];
        for chunk in rnd.chunks_mut(8) {
            chunk.copy_from_slice(&xs(&mut seed).to_le_bytes());
        }
        match (xs(&mut seed) % 4) as u8 {
            0 => ic[0] = rnd,
            1 => ic[1] = rnd,
            2 => oc[0] = rnd,
            _ => oc[1] = rnd,
        }
        total += 1;
        if !transfer::verify_transfer(&ic, &oc, fee, &proof) { rejected += 1; }
    }

    println!("adversarial public inputs: {rejected}/{total} altered statements rejected");
    assert_eq!(rejected, total, "a valid proof verified under an ALTERED public input — soundness break");
    // and the honest statement still verifies after all the perturbations.
    assert!(transfer::verify_transfer(&in_c, &out_c, fee, &proof));
}

#[test]
fn proof_for_one_statement_does_not_verify_for_another() {
    // Two genuinely different transfers; neither proof may verify against the other's statement.
    let (a_in, a_out, a_p) = transfer::prove_transfer(&[(10, 1), (7, 2)], &[(12, 3), (4, 4)], 1).unwrap();
    let (b_in, b_out, b_p) = transfer::prove_transfer(&[(9, 5), (9, 6)], &[(8, 7), (10, 8)], 0).unwrap();
    assert!(transfer::verify_transfer(&a_in, &a_out, 1, &a_p));
    assert!(transfer::verify_transfer(&b_in, &b_out, 0, &b_p));
    assert!(!transfer::verify_transfer(&b_in, &b_out, 0, &a_p), "A's proof must not prove B");
    assert!(!transfer::verify_transfer(&a_in, &a_out, 1, &b_p), "B's proof must not prove A");
}
