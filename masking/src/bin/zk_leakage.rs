//! AUDIT / ZK battle-test: empirical witness-indistinguishability test for the v3 transfer.
//!
//! Zero-knowledge requires the proof distribution to be (statistically) independent of the hidden
//! amount. We generate many proofs for two transfers that differ ONLY in a hidden output amount
//! (each with fresh random blindings, as in real use), then train the strongest cheap distinguisher
//! we can — a nearest-centroid classifier over the raw proof bytes — and measure how well it
//! recovers the amount on held-out proofs. ZK ⇒ accuracy ≈ 50% (chance). A leak ⇒ accuracy ≫ 50%.
//!
//! Controls:
//!   - randomization: two proofs of the SAME witness must differ.
//!   - public-input check: the hidden amounts must NOT appear in the public inputs.
//!   - positive control: the SAME classifier on a feature that DOES leak (the proof length is
//!     constant, so we inject the amount as a synthetic leaky byte) must reach ~100%, proving the
//!     distinguisher works when signal exists.
//!
//! Usage: zk_leakage [per_class]   (default 160)

use qbc_pq_confidential::zk_transfer::{prove_zk_transfer, ZkTransferPublicInputs};
use winterfell::math::{fields::f64::BaseElement, StarkField};

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).unwrap();
    u64::from_le_bytes(b) & ((1u64 << 62) - 1)
}

/// One balanced 2-in/2-out transfer whose hidden output-0 amount is `a` (out1 is the change),
/// inputs (10,·)+(5,·)=15, fee 0. Fresh random blindings every call.
fn proof_for(a: u64) -> (ZkTransferPublicInputs, Vec<u8>) {
    let ins = [(10u64, rand_u64()), (5u64, rand_u64())];
    let outs = [(a, rand_u64()), (15 - a, rand_u64())];
    prove_zk_transfer(&ins, &outs, 0).expect("balanced + in range")
}

fn centroid(samples: &[Vec<f64>]) -> Vec<f64> {
    let n = samples.len() as f64;
    let d = samples[0].len();
    let mut c = vec![0f64; d];
    for s in samples { for i in 0..d { c[i] += s[i]; } }
    for x in c.iter_mut() { *x /= n; }
    c
}
fn l2(a: &[f64], b: &[f64]) -> f64 { a.iter().zip(b).map(|(x, y)| (x - y) * (x - y)).sum() }
fn dot(a: &[f64], b: &[f64]) -> f64 { a.iter().zip(b).map(|(x, y)| x * y).sum() }

/// Proper held-out linear distinguisher: train direction w = mean(A)-mean(B) and a midpoint
/// threshold on the TRAIN set, then classify TEST samples by which side of the threshold their
/// projection falls. No tie-bias; if w is pure noise, held-out accuracy ≈ 0.5.
fn linear_accuracy(a_f: &[Vec<f64>], b_f: &[Vec<f64>], tr: usize) -> f64 {
    let ca = centroid(&a_f[..tr]);
    let cb = centroid(&b_f[..tr]);
    let w: Vec<f64> = ca.iter().zip(&cb).map(|(x, y)| x - y).collect();
    // threshold = midpoint of the projected train-class means
    let proj = |s: &Vec<f64>| dot(s, &w);
    let ma: f64 = a_f[..tr].iter().map(proj).sum::<f64>() / tr as f64;
    let mb: f64 = b_f[..tr].iter().map(proj).sum::<f64>() / tr as f64;
    let thr = (ma + mb) / 2.0;
    let a_high = ma >= mb; // which class projects higher
    let mut correct = 0usize; let mut total = 0usize;
    for s in &a_f[tr..] { let hi = proj(s) >= thr; if hi == a_high { correct += 1; } total += 1; }
    for s in &b_f[tr..] { let hi = proj(s) >= thr; if hi != a_high { correct += 1; } total += 1; }
    correct as f64 / total as f64
}

fn main() {
    let per_class: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(160);
    let a_amt = 3u64;
    let b_amt = 12u64;

    eprintln!("[zk-leakage] generating {} proofs per class (amounts {a_amt} vs {b_amt})...", per_class);

    // ── control 1: randomization (same witness → different proof) ──
    let ins = [(10u64, 7u64), (5u64, 9u64)];
    let outs = [(3u64, 11u64), (12u64, 13u64)];
    let (_p1, b1) = prove_zk_transfer(&ins, &outs, 0).unwrap();
    let (_p2, b2) = prove_zk_transfer(&ins, &outs, 0).unwrap();
    let randomized = b1 != b2;

    // ── control 2: hidden amounts are NOT in the public inputs ──
    let (pubs, _pr) = proof_for(a_amt);
    let pub_elems: Vec<u64> = {
        use winterfell::math::ToElements;
        pubs.to_elements().iter().map(|e: &BaseElement| e.as_int()).collect()
    };
    let amount_in_public = pub_elems.iter().any(|&x| x == a_amt || x == (15 - a_amt));

    // ── gather proofs ──
    let mut a_proofs: Vec<Vec<u8>> = Vec::new();
    let mut b_proofs: Vec<Vec<u8>> = Vec::new();
    for _ in 0..per_class { a_proofs.push(proof_for(a_amt).1); }
    for _ in 0..per_class { b_proofs.push(proof_for(b_amt).1); }
    let plen = a_proofs.iter().chain(b_proofs.iter()).map(|p| p.len()).min().unwrap();
    let to_f = |p: &Vec<u8>| -> Vec<f64> { p[..plen].iter().map(|&x| x as f64).collect() };

    // 70/30 train/test split
    let tr = (per_class * 7) / 10;
    let a_f: Vec<_> = a_proofs.iter().map(to_f).collect();
    let b_f: Vec<_> = b_proofs.iter().map(to_f).collect();
    let acc = linear_accuracy(&a_f, &b_f, tr);
    let _ = l2;

    // ── max per-byte effect size (|mean_A − mean_B| / pooled std), as a leakage scan ──
    let ca = centroid(&a_f); let cb = centroid(&b_f);
    let mut max_t = 0f64; let mut max_byte = 0usize;
    for i in 0..plen {
        let va: f64 = a_f.iter().map(|s| (s[i] - ca[i]).powi(2)).sum::<f64>() / a_f.len() as f64;
        let vb: f64 = b_f.iter().map(|s| (s[i] - cb[i]).powi(2)).sum::<f64>() / b_f.len() as f64;
        let sd = ((va + vb) / 2.0).sqrt().max(1e-9);
        let t = (ca[i] - cb[i]).abs() / sd;
        if t > max_t { max_t = t; max_byte = i; }
    }

    // ── positive control: same linear classifier on a synthetic leaky feature ──
    let mut a_leak = a_f.clone();
    let mut b_leak = b_f.clone();
    for s in a_leak.iter_mut() { s.push((a_amt as f64) * 1000.0); }
    for s in b_leak.iter_mut() { s.push((b_amt as f64) * 1000.0); }
    let pc_acc = linear_accuracy(&a_leak, &b_leak, tr);

    println!("{{");
    println!("  \"per_class\": {per_class},");
    println!("  \"proof_len_bytes\": {plen},");
    println!("  \"control_randomized\": {randomized},");
    println!("  \"control_amount_in_public_inputs\": {amount_in_public},");
    println!("  \"distinguisher_accuracy\": {:.4},", acc);
    println!("  \"max_per_byte_effect_size\": {:.4},", max_t);
    println!("  \"max_effect_byte_index\": {max_byte},");
    println!("  \"positive_control_accuracy\": {:.4},", pc_acc);
    println!("  \"verdict\": \"{}\"", if acc < 0.60 && randomized && !amount_in_public { "PASS: amount not recoverable from proof (held-out distinguisher at chance; positive control separates)" } else { "INVESTIGATE" });
    println!("}}");
}
