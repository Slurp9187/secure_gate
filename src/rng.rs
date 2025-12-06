// src/rng.rs
//! Cryptographically secure random generation for fixed-size and dynamic secrets.
//!
//! This module provides specialized types for random secrets:
//! - `FixedRng<N>`: Fixed-size random bytes (e.g., keys, nonces).
//! - `DynamicRng`: Variable-length random bytes (e.g., salts, tokens).
//!
//! Both types use a thread-local `rand::rngs::OsRng` that is lazily
//! initialized on first use. Features:
//! - Zero heap allocation after first use (for fixed-size).
//! - Fully `no_std`-compatible.
//! - Panics on RNG failure (standard in high-assurance crypto).
//!
//! # Examples
//!
//! ```
//! use secure_gate::rng::{DynamicRng, FixedRng};
//!
//! let key = FixedRng::<32>::rng();     // Correct: generates random
//! let salt = DynamicRng::rng(16);      // Correct: generates random
//!
//! assert_eq!(key.len(), 32);
//! assert_eq!(salt.len(), 16);
//! ```

use crate::{Dynamic, Fixed};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::cell::RefCell;

thread_local! {
    static OS_RNG: RefCell<OsRng> = const { RefCell::new(OsRng) };
}

/// Fixed-size random-only secret.
pub struct FixedRng<const N: usize>(Fixed<[u8; N]>);

impl<const N: usize> FixedRng<N> {
    /// Generate a new instance filled with cryptographically secure randomness.
    ///
    /// This is the **only** way to construct a `FixedRng` — there is no `new()` that takes data.
    #[inline(always)]
    pub fn rng() -> Self {
        let mut bytes = [0u8; N];
        OS_RNG.with(|rng| {
            rng.borrow_mut()
                .try_fill_bytes(&mut bytes)
                .expect("OsRng failed to fill bytes — this should never happen");
        });
        Self(Fixed::new(bytes))
    }

    /// Expose the secret bytes.
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8; N] {
        self.0.expose_secret()
    }
}

impl<const N: usize> core::ops::Deref for FixedRng<N> {
    type Target = Fixed<[u8; N]>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for FixedRng<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> core::fmt::Debug for FixedRng<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED_RANDOM]")
    }
}

impl<const N: usize> Default for FixedRng<N> {
    /// Convenience: `Default` generates random bytes.
    ///
    /// Allows `let key = FixedRng::<32>::default();`
    #[inline(always)]
    fn default() -> Self {
        Self::rng()
    }
}

/// Dynamic-size random-only secret (always backed by `Vec<u8>`).
pub struct DynamicRng(Dynamic<Vec<u8>>);

impl DynamicRng {
    /// Generate a new instance of the given length filled with cryptographically secure randomness.
    ///
    /// This is the **only** way to construct a `DynamicRng`.
    #[inline(always)]
    pub fn rng(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OS_RNG.with(|rng| {
            rng.borrow_mut()
                .try_fill_bytes(&mut bytes)
                .expect("OsRng failed to fill bytes — this should never happen");
        });
        Self(Dynamic::new(bytes))
    }

    /// Expose the secret bytes as a slice.
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }
}

impl core::ops::Deref for DynamicRng {
    type Target = Dynamic<Vec<u8>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for DynamicRng {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::fmt::Debug for DynamicRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED_RANDOM]")
    }
}

/// Optional: convenience trait if users want to write `FixedRng::<32>::random()`
///
/// This is **not required** by issue #27 — in fact, avoiding it is better for clarity.
/// But if you want to keep backward compatibility or ergonomics, this is safe.
#[cfg(feature = "rand")]
pub trait SecureRandomExt {
    fn rng() -> Self
    where
        Self: Sized;
}

#[cfg(feature = "rand")]
impl<const N: usize> SecureRandomExt for FixedRng<N> {
    #[inline(always)]
    fn rng() -> Self {
        Self::rng()
    }
}
