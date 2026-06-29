//! Plonky3 reimplementation of the QBC post-quantum confidential circuits (research branch).
//! `no_std` by default for the verify path (runtime); the `prover` feature (default) adds std + the
//! prover (trace generation + getrandom-seeded hiding randomness).
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg_attr(not(feature = "std"), macro_use)]
extern crate alloc;

pub mod constants;
pub mod rescue;
pub mod config;
pub mod opening;
pub mod open_pub;
pub mod transfer;
