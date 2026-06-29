//! Goldilocks zero-knowledge StarkConfig on Plonky3's `HidingFriPcs` (native FRI ZK).
//!
//! The verify config is `no_std` (a fixed RNG seed, since the verifier never draws hiding
//! randomness). The prover config (behind the `prover` feature) seeds a CSPRNG (ChaCha20) from
//! full 256-bit OS entropy so each proof gets fresh salts and random codewords.
//!
//! AUDIT FIX (F4, reviewer finding): the hiding RNG was `SmallRng` (a non-cryptographic xoshiro
//! generator) seeded from a single 64-bit value. That throttled the salt / random-codeword entropy
//! to 64 bits and voided the "hiding is inherited from the proving system" claim. We now use
//! `ChaCha20Rng` (a CSPRNG) and seed the two generators with two INDEPENDENT 256-bit draws from the
//! OS, so the masking entropy is full-strength and the two RNG streams are not correlated.

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Goldilocks, 2>;
pub type Perm = Poseidon2Goldilocks<8>;
pub type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
pub type ValMmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    MyHash,
    MyCompress,
    ChaCha20Rng,
    2,
    4,
    4,
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel<Val>;
pub type MyPcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, ChaCha20Rng>;
pub type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
pub type ZkConfig = StarkConfig<MyPcs, Challenge, Challenger>;

/// FRI parameters. log_blowup sized for the (symbolically-derived) Rescue constraint degree.
fn fri_params(challenge_mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 32,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
}

fn build(rng_mmcs: ChaCha20Rng, rng_pcs: ChaCha20Rng) -> ZkConfig {
    let perm = default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0, rng_mmcs);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let pcs = MyPcs::new(dft, val_mmcs, fri_params(challenge_mmcs), 4, rng_pcs);
    let challenger = Challenger::new(perm);
    ZkConfig::new(pcs, challenger)
}

/// Verifier config (no_std): the RNG seed is irrelevant to verification (the verifier draws no
/// hiding randomness), so it is fixed.
pub fn zk_config_verify() -> ZkConfig {
    build(ChaCha20Rng::from_seed([0u8; 32]), ChaCha20Rng::from_seed([0u8; 32]))
}

/// Prover config (std): two INDEPENDENT 256-bit OS-entropy seeds drive the salts / random
/// codewords (hiding). ChaCha20 is a CSPRNG, so the masked rows and random codewords are
/// computationally indistinguishable from uniform — the hiding is full-strength, not throttled
/// through a 64-bit seed as before (AUDIT FIX F4).
#[cfg(feature = "prover")]
pub fn zk_config() -> ZkConfig {
    let mut seed_mmcs = [0u8; 32];
    let mut seed_pcs = [0u8; 32];
    getrandom::fill(&mut seed_mmcs).expect("os entropy");
    getrandom::fill(&mut seed_pcs).expect("os entropy");
    build(
        ChaCha20Rng::from_seed(seed_mmcs),
        ChaCha20Rng::from_seed(seed_pcs),
    )
}
