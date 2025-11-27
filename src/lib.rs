// src/lib.rs
//! # secure-gate: Zero-cost secure wrappers for secrets
//!
//! Provides safe, ergonomic handling of sensitive data in memory with zero runtime overhead.
//!
//! - **Fixed&lt;T&gt;**: Stack-allocated for fixed-size secrets (e.g., keys, nonces)
//! - **Dynamic&lt;T&gt;**: Heap-allocated for dynamic secrets (e.g., passwords, vectors)
//! - **Zeroizing variants**: Automatic memory wiping on drop (with `zeroize` feature)
//! - **Macros**: `fixed_alias!`, `dynamic_alias!`, `secure!`, `secure_zeroizing!` for beautiful syntax
//!
//! # Features
//!
//! - `zeroize`: Enables auto-wiping on drop
//! - `serde`: Optional serialization support
//! - Works in `no_std` + `alloc` environments
//!
//! # Quick Start
//!
//! ```
//! use secure_gate::{Dynamic, Fixed, fixed_alias, dynamic_alias};
//!
//! fixed_alias!(Aes256Key, 32);
//! dynamic_alias!(Password, String);
//!
//! let key: Aes256Key = [42u8; 32].into();
//! let pw: Password = "hunter2".into();
//!
//! assert_eq!(key.expose_secret()[0], 42);
//! assert_eq!(pw.expose_secret(), "hunter2");
//! ```
//!
//! See individual modules for details.

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

// Core modules
mod dynamic;
mod fixed;
mod macros;

// Feature-gated modules
#[cfg(feature = "zeroize")]
mod zeroize;

#[cfg(feature = "serde")]
mod serde;

// Public API
pub use dynamic::Dynamic;
pub use fixed::Fixed;

// Zeroize integration (opt-in)
#[cfg(feature = "zeroize")]
pub use zeroize::{DynamicZeroizing, FixedZeroizing};

// Re-export Zeroizing cleanly — no privacy conflict
#[cfg(feature = "zeroize")]
pub type Zeroizing<T> = ::zeroize::Zeroizing<T>;

// Re-export the trait and marker directly from the zeroize crate
#[cfg(feature = "zeroize")]
pub use ::zeroize::{Zeroize, ZeroizeOnDrop};

// lib.rs
#[cfg(feature = "rand")]
pub mod rng;
#[cfg(feature = "rand")]
pub use rng::SecureRandomExt;
