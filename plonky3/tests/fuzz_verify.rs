// Panic-safety fuzz: the verifier must NEVER panic on adversarial input (it must return false).
// A panic in an in-runtime verifier is a block-production / halt risk, so this is a deploy gate.
use qbc_pq_confidential_p3::{transfer, opening, open_pub};
use std::panic::catch_unwind;

fn rng_bytes(seed: &mut u64, n: usize) -> Vec<u8> {
    // tiny xorshift, deterministic, std-free entropy not needed for fuzz vectors
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        *seed ^= *seed << 13; *seed ^= *seed >> 7; *seed ^= *seed << 17;
        v.push((*seed & 0xff) as u8);
    }
    v
}

#[test]
fn verifier_never_panics_on_adversarial_input() {
    // a valid baseline proof to mutate
    let (in_c, out_c, good) = transfer::prove_transfer(&[(10,111),(7,222)], &[(12,333),(4,444)], 1).unwrap();
    let (oc, gopen) = opening::prove_open(5, 9);
    let (pc, gpub) = open_pub::prove_open_pub(5, 9, &[0x66u8;32]);

    let c0 = [0u8;32]; let _ = (c0, oc, pc);
    let mut panics = 0u64;
    let mut checks = 0u64;
    let mut seed = 0x1234_5678_9abc_def0u64;

    let mut guard = |f: &(dyn Fn() -> bool + std::panic::RefUnwindSafe)| {
        checks += 1;
        if catch_unwind(|| f()).is_err() { panics += 1; }
    };

    // 1. random byte vectors of many lengths as the "proof"
    for _ in 0..3000 {
        let n = (seed as usize) % 4096;
        let bytes = rng_bytes(&mut seed, n);
        let b2 = bytes.clone(); let b3 = bytes.clone();
        guard(&move || transfer::verify_transfer(&in_c, &out_c, 1, &bytes));
        guard(&move || opening::verify_open(&oc, &b2));
        guard(&move || open_pub::verify_open_pub(&pc, 5, &[0x66u8;32], &b3));
    }
    // 2. single-byte mutations of the valid proofs
    for i in (0..good.len()).step_by(97) {
        let mut m = good.clone(); m[i] ^= 0xff;
        let mm = m.clone();
        guard(&move || transfer::verify_transfer(&in_c, &out_c, 1, &mm));
    }
    for i in (0..gopen.len()).step_by(97) {
        let mut m = gopen.clone(); m[i] ^= 0xff; let mm = m.clone();
        guard(&move || opening::verify_open(&oc, &mm));
    }
    for i in (0..gpub.len()).step_by(97) {
        let mut m = gpub.clone(); m[i] ^= 0xff; let mm = m.clone();
        guard(&move || open_pub::verify_open_pub(&pc, 5, &[0x66u8;32], &mm));
    }
    // 3. truncations of the valid transfer proof
    for cut in (0..good.len()).step_by(257) {
        let t = good[..cut].to_vec();
        guard(&move || transfer::verify_transfer(&in_c, &out_c, 1, &t));
    }
    // 4. sanity: the good proofs still verify (no false negatives from the harness)
    assert!(transfer::verify_transfer(&in_c, &out_c, 1, &good));
    assert!(opening::verify_open(&oc, &gopen));
    assert!(open_pub::verify_open_pub(&pc, 5, &[0x66u8;32], &gpub));

    println!("FUZZ: {checks} adversarial verifications, {panics} panics");
    assert_eq!(panics, 0, "verifier panicked on adversarial input ({panics}/{checks}) — halt risk, must fix before deploy");
}
