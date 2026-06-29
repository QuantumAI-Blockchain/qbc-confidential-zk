use qbc_pq_confidential_p3::{open_pub, rescue};
use open_pub::SHIELD_CONTEXT;

#[test]
fn p3_pubopen_value_public_and_context_bound() {
    let (v, b) = (1_000_000u64, 0xABCDu64);
    let dest = [0x66u8; 32];
    // unshield-style: bound to dest
    let (c, p) = open_pub::prove_open_pub(v, b, &dest);
    assert_eq!(c, rescue::commit_bytes(v, b), "commitment matches live chain");
    assert!(open_pub::verify_open_pub(&c, v, &dest, &p), "valid pub-open verifies");
    // wrong public value rejected (no inflation)
    assert!(!open_pub::verify_open_pub(&c, v + 1, &dest, &p), "wrong value rejected");
    // wrong context (re-pointed dest) rejected
    let attacker = [0xEEu8; 32];
    assert!(!open_pub::verify_open_pub(&c, v, &attacker, &p), "re-pointed destination rejected");
    // shield-style sentinel
    let (cs, ps) = open_pub::prove_open_pub(v, b, &SHIELD_CONTEXT);
    assert!(open_pub::verify_open_pub(&cs, v, &SHIELD_CONTEXT, &ps));
    assert!(!open_pub::verify_open_pub(&cs, v, &dest, &ps), "shield proof not usable as unshield-to-dest");
    println!("p3 public-value opening: value public, no-inflation + dest-binding hold. proof_bytes={}", p.len());
}
