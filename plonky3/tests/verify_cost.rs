// Measure native verify cost (informs in-block feasibility; the runtime wasm verify is slower but
// this gives the order of magnitude).
use qbc_pq_confidential_p3::{transfer, opening};
use std::time::Instant;

#[test]
fn verify_cost_report() {
    let (in_c, out_c, tp) = transfer::prove_transfer(&[(10,111),(7,222)], &[(12,333),(4,444)], 1).unwrap();
    let (oc, op) = opening::prove_open(5, 9);
    let n = 50;
    let t0 = Instant::now();
    for _ in 0..n { assert!(transfer::verify_transfer(&in_c, &out_c, 1, &tp)); }
    let tv = t0.elapsed().as_secs_f64() * 1000.0 / n as f64;
    let t1 = Instant::now();
    for _ in 0..n { assert!(opening::verify_open(&oc, &op)); }
    let ov = t1.elapsed().as_secs_f64() * 1000.0 / n as f64;
    println!("VERIFY COST (native): transfer {:.2} ms ({} B), opening {:.2} ms ({} B)", tv, tp.len(), ov, op.len());
}
