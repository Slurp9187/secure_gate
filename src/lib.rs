// ==========================================================================
// src/lib.rs
// ==========================================================================

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
#![doc = include_str!("../README.md")]

extern crate alloc;

// ── Core secret types (always available) ─────────────────────────────
mod dynamic;
mod fixed;

pub use dynamic::Dynamic;
pub use fixed::Fixed;

// ── Non-cloneable wrappers (always available, zero-cost, pure) ───────
mod no_clone;
pub use no_clone::{DynamicNoClone, FixedNoClone};

// ── Macros (always available) ────────────────────────────────────────
mod macros;

// // Re-export the macros at the crate root so users can just `use secure_gate::fixed_alias;`
// pub use macros::{
//     dynamic_alias, dynamic_generic_alias, fixed_alias, fixed_alias_rng, fixed_generic_alias,
// };

// ── Feature-gated modules (zero compile-time cost when disabled) ─────
#[cfg(feature = "rand")]
pub mod rng;

#[cfg(feature = "conversions")]
pub mod conversions;

// ── Feature-gated re-exports ─────────────────────────────────────────
#[cfg(feature = "rand")]
pub use rng::{DynamicRng, FixedRng};

#[cfg(feature = "conversions")]
pub use conversions::{HexString, RandomHex, SecureConversionsExt};
