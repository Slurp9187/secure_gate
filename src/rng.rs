// src/rng.rs
//! Cryptographically secure random generation for fixed-size secrets.
//!
//! This module provides the [`SecureRandomExt`] trait, which adds a `.random()`
//! method to all `Fixed<[u8; N]>` types (including those created via [`fixed_alias!`]).
//!
//! The implementation uses a **thread-local** `rand::rngs::OsRng` that is lazily
//! initialized on first use. It is:
//! - Zero heap allocation after first use
//! - Fully `no_std`-compatible
//! - Panics on RNG failure (standard practice in high-assurance crypto code)
//!
//! Requires the `rand` feature.
//!
//! # Examples
//!
//! ```
//! use secure_gate::{fixed_alias, SecureRandomExt};
//!
//! fixed_alias!(Aes256Key, 32);
//! fixed_alias!(XChaCha20Nonce, 24);
//!
//! let key: Aes256Key = Aes256Key::random();        // cryptographically secure
//! let nonce: XChaCha20Nonce = XChaCha20Nonce::random();
//!
//! assert_eq!(key.len(), 32);
//! assert_eq!(nonce.len(), 24);
//! ```

use rand::{rngs::OsRng, TryRngCore};
use std::cell::RefCell;

thread_local! {
    static OS_RNG: RefCell<OsRng> = const { RefCell::new(OsRng) };
}

/// Extension trait for generating cryptographically secure random values.
///
/// Implemented for all `Fixed<[u8; N]>` types (including `fixed_alias!` types).
///
/// # Panics
///
/// Panics if the OS RNG fails to fill the buffer. This is exceedingly rare and
/// considered fatal in cryptographic contexts.
pub trait SecureRandomExt {
    /// Generates a new random instance using the operating system's
    /// cryptographically secure PRNG.
    fn random() -> Self;
}

impl<const N: usize> SecureRandomExt for crate::Fixed<[u8; N]> {
    #[inline(always)]
    fn random() -> Self {
        OS_RNG.with(|rng| {
            let mut rng = rng.borrow_mut();
            let mut bytes = [0u8; N];
            rng.try_fill_bytes(&mut bytes)
                .expect("OsRng failed to fill bytes — this should never happen");
            Self::new(bytes)
        })
    }
}
