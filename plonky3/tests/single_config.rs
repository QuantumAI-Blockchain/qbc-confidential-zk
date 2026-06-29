use qbc_pq_confidential_p3::config::zk_config;
use qbc_pq_confidential_p3::opening::{build_trace, OpeningAir};
use p3_uni_stark::{prove, verify};

#[test]
fn single_shared_config_roundtrip() {
    let config = zk_config();
    let (trace, pis) = build_trace(1_527_000_000, 0xDEAD_BEEF);
    let proof = prove(&config, &OpeningAir, trace, &pis);
    match verify(&config, &OpeningAir, &proof, &pis) {
        Ok(()) => println!("SINGLE-CONFIG: verify OK"),
        Err(e) => panic!("SINGLE-CONFIG verify failed: {e:?}"),
    }
}
