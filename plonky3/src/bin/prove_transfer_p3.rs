//! Emit a real Plonky3 v4 transfer proof + its commitments as hex, for driving a live
//! confidential_transfer_v4 battle-test. Args (optional): v_in0 b_in0 v_in1 b_in1 v_out0 b_out0
//! v_out1 b_out1 fee. Defaults to a balanced 10+7 -> 12+4 + fee 1.
use qbc_pq_confidential_p3::transfer;

fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn main() {
    let a: Vec<u64> = std::env::args().skip(1).filter_map(|s| s.parse().ok()).collect();
    let g = |i: usize, d: u64| *a.get(i).unwrap_or(&d);
    let ins = [(g(0, 10), g(1, 111)), (g(2, 7), g(3, 222))];
    let outs = [(g(4, 12), g(5, 333)), (g(6, 4), g(7, 444))];
    let fee = g(8, 1);
    let (in_c, out_c, proof) =
        transfer::prove_transfer(&ins, &outs, fee).expect("balanced + in-range");
    println!("in0 {}", hx(&in_c[0]));
    println!("in1 {}", hx(&in_c[1]));
    println!("out0 {}", hx(&out_c[0]));
    println!("out1 {}", hx(&out_c[1]));
    println!("fee {}", fee);
    println!("proof {}", hx(&proof));
    eprintln!("proof_bytes={}", proof.len());
}
