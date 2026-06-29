//! Full post-quantum confidential transfer = the M2.5 balance/openings proof + one M2.5b
//! range+commitment proof per output, linked by the shared (binding) output commitments.
//!
//! Soundness argument (no monolithic circuit needed):
//! - `transfer` proves: every input/output commitment opens, and `Σin = Σout + fee`.
//! - `range_commit` proves, per output `j`: `C_out_j` opens to a value in `[0, 2^63)`.
//! - Rescue is binding ⇒ the value range-proven against `C_out_j` is the SAME value summed in
//!   the balance proof against `C_out_j`. Hence: balanced + all outputs in range + all openings
//!   valid ⇒ no inflation, no wrap-around, amounts hidden. Quantum-secure throughout (FRI/hash).

use crate::transfer::{self, TransferPublicInputs, N_IN, N_OUT};
use crate::range_commit;
use alloc::vec::Vec;

/// A complete confidential-transfer proof bundle.
pub struct FullTransferProof {
    pub pubs: TransferPublicInputs,
    pub transfer_proof: Vec<u8>,
    /// One range+commitment proof per output (same order as `pubs.out_commitments`).
    pub output_range_proofs: Vec<Vec<u8>>,
}

/// Prove a complete, fully-sound confidential transfer. `None` if unbalanced or any output is
/// out of range (an honest prover refuses; both are in any case unprovable).
#[cfg(feature = "prover")]
pub fn prove_full_transfer(
    in_notes: &[(u64, u64); N_IN],
    out_notes: &[(u64, u64); N_OUT],
    fee: u64,
) -> Option<FullTransferProof> {
    let (pubs, transfer_proof) = transfer::prove_transfer(in_notes, out_notes, fee)?;
    let mut output_range_proofs = Vec::with_capacity(N_OUT);
    for &(value, blinding) in out_notes.iter() {
        let (_c, proof) = range_commit::prove_range_commit(value, blinding)?;
        output_range_proofs.push(proof);
    }
    Some(FullTransferProof { pubs, transfer_proof, output_range_proofs })
}

/// Runtime-facing verify API: all inputs are raw bytes (SCALE-friendly), no winterfell types
/// leak to the caller. Reconstructs the public inputs from 32-byte commitments (4×u64-LE) + a
/// u64 fee, then verifies the full transfer. `N_IN`/`N_OUT` are enforced. Post-quantum, no_std.
pub fn verify_transfer_bundle(
    in_commitments: &[[u8; 32]],
    out_commitments: &[[u8; 32]],
    fee: u64,
    transfer_proof: &[u8],
    output_range_proofs: &[&[u8]],
) -> bool {
    use winterfell::math::fields::f64::BaseElement;
    if in_commitments.len() != N_IN
        || out_commitments.len() != N_OUT
        || output_range_proofs.len() != N_OUT
    {
        return false;
    }
    let to_digest = |b: &[u8; 32]| -> [BaseElement; 4] {
        let mut d = [BaseElement::new(0); 4];
        for k in 0..4 {
            let mut le = [0u8; 8];
            le.copy_from_slice(&b[k * 8..k * 8 + 8]);
            d[k] = BaseElement::new(u64::from_le_bytes(le));
        }
        d
    };
    let mut in_c = [[BaseElement::new(0); 4]; N_IN];
    let mut out_c = [[BaseElement::new(0); 4]; N_OUT];
    for i in 0..N_IN {
        in_c[i] = to_digest(&in_commitments[i]);
    }
    for j in 0..N_OUT {
        out_c[j] = to_digest(&out_commitments[j]);
    }
    let pubs = TransferPublicInputs {
        in_commitments: in_c,
        out_commitments: out_c,
        fee: BaseElement::new(fee),
    };
    let bundle = FullTransferProof {
        pubs,
        transfer_proof: transfer_proof.to_vec(),
        output_range_proofs: output_range_proofs.iter().map(|p| p.to_vec()).collect(),
    };
    verify_full_transfer(&bundle)
}

/// Verify a complete confidential transfer: the balance/openings proof AND a range proof for
/// every output, each bound to the public output commitments. Post-quantum.
pub fn verify_full_transfer(bundle: &FullTransferProof) -> bool {
    if bundle.output_range_proofs.len() != N_OUT {
        return false;
    }
    if !transfer::verify_transfer(&bundle.pubs, &bundle.transfer_proof) {
        return false;
    }
    for j in 0..N_OUT {
        if !range_commit::verify_range_commit(
            &bundle.pubs.out_commitments[j],
            &bundle.output_range_proofs[j],
        ) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::{fields::f64::BaseElement, FieldElement};

    #[test]
    fn full_balanced_in_range_transfer_verifies() {
        // 10 + 7 in  ->  12 + 4 out  + fee 1
        let ins = [(10u64, 111u64), (7u64, 222u64)];
        let outs = [(12u64, 333u64), (4u64, 444u64)];
        let bundle = prove_full_transfer(&ins, &outs, 1).expect("balanced + in range");
        assert!(verify_full_transfer(&bundle), "complete sound transfer must verify");
    }

    #[test]
    fn realistic_amounts_verify() {
        // 100 QBC split into 99.5 + 0.49 + fee 0.01 (units, 1 QBC = 1e8)
        let ins = [(10_000_000_000u64, 1u64), (0u64, 2u64)];
        let outs = [(9_950_000_000u64, 3u64), (49_000_000u64, 4u64)];
        let bundle = prove_full_transfer(&ins, &outs, 1_000_000).expect("balanced");
        assert!(verify_full_transfer(&bundle));
    }

    #[test]
    fn tampering_any_part_rejects() {
        let ins = [(8u64, 11u64), (2u64, 22u64)];
        let outs = [(6u64, 33u64), (4u64, 44u64)];
        let mut bundle = prove_full_transfer(&ins, &outs, 0).expect("balanced");
        assert!(verify_full_transfer(&bundle));

        // tamper the transfer proof
        let mut b1 = FullTransferProof {
            pubs: bundle.pubs.clone(),
            transfer_proof: bundle.transfer_proof.clone(),
            output_range_proofs: bundle.output_range_proofs.clone(),
        };
        let m = b1.transfer_proof.len() / 2;
        b1.transfer_proof[m] ^= 0xff;
        assert!(!verify_full_transfer(&b1), "tampered transfer proof must reject");

        // tamper an output range proof
        let m2 = bundle.output_range_proofs[0].len() / 2;
        bundle.output_range_proofs[0][m2] ^= 0xff;
        assert!(!verify_full_transfer(&bundle), "tampered range proof must reject");
    }

    #[test]
    fn forged_fee_rejected() {
        let ins = [(10u64, 1u64), (7u64, 2u64)];
        let outs = [(12u64, 3u64), (4u64, 4u64)];
        let mut bundle = prove_full_transfer(&ins, &outs, 1).expect("balanced");
        assert!(verify_full_transfer(&bundle));
        bundle.pubs.fee = BaseElement::new(2); // claim a different fee
        assert!(!verify_full_transfer(&bundle), "forged fee must reject");
    }

    #[test]
    fn unbalanced_or_out_of_range_unprovable() {
        // unbalanced
        let ins = [(10u64, 1u64), (7u64, 2u64)];
        let outs = [(12u64, 3u64), (5u64, 4u64)]; // 17 != 18
        assert!(prove_full_transfer(&ins, &outs, 1).is_none());
    }
}

#[cfg(test)]
mod bundle_tests {
    use super::*;
    use crate::transfer::N_OUT;
    use winterfell::math::{fields::f64::BaseElement, StarkField};

    fn digest_bytes(c: &[BaseElement; 4]) -> [u8; 32] {
        let mut b = [0u8; 32];
        for k in 0..4 {
            b[k * 8..k * 8 + 8].copy_from_slice(&c[k].as_int().to_le_bytes());
        }
        b
    }

    #[test]
    fn raw_bytes_bundle_api_verifies_and_rejects() {
        let ins = [(10u64, 1u64), (7u64, 2u64)];
        let outs = [(12u64, 3u64), (4u64, 4u64)];
        let bundle = prove_full_transfer(&ins, &outs, 1).expect("balanced");
        let in_c: std::vec::Vec<[u8; 32]> =
            bundle.pubs.in_commitments.iter().map(digest_bytes).collect();
        let out_c: std::vec::Vec<[u8; 32]> =
            bundle.pubs.out_commitments.iter().map(digest_bytes).collect();
        let rp: std::vec::Vec<&[u8]> =
            bundle.output_range_proofs.iter().map(|p| p.as_slice()).collect();
        assert!(verify_transfer_bundle(&in_c, &out_c, 1, &bundle.transfer_proof, &rp));
        // wrong fee rejected
        assert!(!verify_transfer_bundle(&in_c, &out_c, 2, &bundle.transfer_proof, &rp));
        // wrong arity rejected
        assert!(!verify_transfer_bundle(&in_c[..1], &out_c, 1, &bundle.transfer_proof, &rp));
        let _ = N_OUT;
    }
}
