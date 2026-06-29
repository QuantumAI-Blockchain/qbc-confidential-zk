//! Emit a Plonky3 v4 public-value opening proof + commitment as hex, for driving live
//! shield_v4 / unshield_v4. Args: value blinding context_hex(64). context = "00"*32 for a shield.
use qbc_pq_confidential_p3::open_pub;
fn hx(b: &[u8]) -> String { let mut s=String::new(); for x in b { s.push_str(&format!("{:02x}",x)); } s }
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let value: u64 = a.get(0).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let blind: u64 = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(42);
    let ctx_hex = a.get(2).cloned().unwrap_or_else(|| "00".repeat(32));
    let mut ctx = [0u8; 32];
    let cb = (0..32).map(|i| u8::from_str_radix(&ctx_hex[i*2..i*2+2],16).unwrap()).collect::<Vec<_>>();
    ctx.copy_from_slice(&cb);
    let (commitment, proof) = open_pub::prove_open_pub(value, blind, &ctx);
    println!("commitment {}", hx(&commitment));
    println!("value {}", value);
    println!("proof {}", hx(&proof));
    eprintln!("proof_bytes={}", proof.len());
}
