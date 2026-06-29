// One-off: emit the Rescue Rp64_256 constants (from the audited Winterfell impl) as u64 arrays,
// so the p3 crate is self-contained and bit-compatible with the live chain's commitments.
use winterfell::crypto::hashers::Rp64_256;
use winterfell::math::{fields::f64::BaseElement, StarkField};

fn row(r: &[BaseElement]) -> String {
    let xs: Vec<String> = r.iter().map(|e| format!("{}", e.as_int())).collect();
    format!("[{}]", xs.join(", "))
}

#[test]
fn emit() {
    let mut s = String::new();
    s.push_str("// AUTO-GENERATED from Winterfell Rp64_256 (the live chain's Rescue). Do not edit.\n");
    s.push_str("pub const STATE_WIDTH: usize = 12;\n");
    s.push_str("pub const NUM_ROUNDS: usize = 7;\n");
    s.push_str("pub const ALPHA: u64 = 7;\n");
    s.push_str("pub const INV_ALPHA: u64 = 10540996611094048183;\n");
    s.push_str("pub const CAPACITY_INIT: u64 = 2;\n\n");
    s.push_str("pub const INV_MDS: [[u64; 12]; 12] = [\n");
    for r in 0..12 { s.push_str(&format!("    {},\n", row(&Rp64_256::INV_MDS[r]))); }
    s.push_str("];\n\n");
    // MDS 12x12
    s.push_str("pub const MDS: [[u64; 12]; 12] = [\n");
    for r in 0..12 { s.push_str(&format!("    {},\n", row(&Rp64_256::MDS[r]))); }
    s.push_str("];\n\n");
    // ARK1 7x12, ARK2 7x12
    s.push_str("pub const ARK1: [[u64; 12]; 7] = [\n");
    for r in 0..7 { s.push_str(&format!("    {},\n", row(&Rp64_256::ARK1[r]))); }
    s.push_str("];\n\n");
    s.push_str("pub const ARK2: [[u64; 12]; 7] = [\n");
    for r in 0..7 { s.push_str(&format!("    {},\n", row(&Rp64_256::ARK2[r]))); }
    s.push_str("];\n");
    std::fs::write("src/constants.rs", s).unwrap();
    eprintln!("wrote src/constants.rs");
}
