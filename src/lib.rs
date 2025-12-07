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

// ── Macros (always available — you want them, but not in root namespace)
mod macros;

// ── Feature-gated modules (zero compile-time cost when disabled) ─────
#[cfg(feature = "rand")]
pub mod rng;

#[cfg(feature = "conversions")]
pub mod conversions;

// ── Feature-gated re-exports (only exist when feature is enabled) ────
#[cfg(feature = "rand")]
pub use rng::{DynamicRng, FixedRng};

#[cfg(feature = "conversions")]
pub use conversions::{HexString, RandomHex, SecureConversionsExt};
