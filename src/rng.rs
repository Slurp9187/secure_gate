// src/rng.rs
//! Cryptographically secure random generation — unified RNG-only types (0.6.0)
//!
//! - `FixedRng<N>` → fixed-size, only via `.rng()`
//! - `DynamicRng` → dynamic-size, only via `.rng(len)` (specialized for Vec<u8>)
//!
//! Freshness is compiler-enforced: no way to construct from existing data.

use crate::{Dynamic, Fixed};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::cell::RefCell;

thread_local! {
    static OS_RNG: RefCell<OsRng> = const { RefCell::new(OsRng) };
}

/// Fixed-size random-only secret (e.g. `fixed_alias_rng!(Aes256Key, 32)`)
pub struct FixedRng<const N: usize>(Fixed<[u8; N]>);

impl<const N: usize> FixedRng<N> {
    /// Generate cryptographically secure random bytes.
    ///
    /// This is the **only** way to construct this type.
    #[inline(always)]
    pub fn rng() -> Self {
        let mut bytes = [0u8; N];
        OS_RNG.with(|rng| {
            let _ = (*rng.borrow_mut()).try_fill_bytes(&mut bytes);
        });
        Self(Fixed(bytes))
    }

    /// Expose the secret bytes.
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0 .0
    }
}

impl<const N: usize> core::ops::Deref for FixedRng<N> {
    type Target = Fixed<[u8; N]>;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for FixedRng<N> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> core::fmt::Debug for FixedRng<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED_RANDOM]")
    }
}

/// Dynamic-size random-only secret (specialized for Vec<u8>)
pub struct DynamicRng(Dynamic<Vec<u8>>);

impl DynamicRng {
    /// Generate exactly `len` cryptographically secure random bytes.
    ///
    /// This is the **only** way to construct this type.
    #[inline(always)]
    pub fn rng(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OS_RNG.with(|rng| {
            let _ = (*rng.borrow_mut()).try_fill_bytes(&mut bytes);
        });
        Self(Dynamic(Box::new(bytes)))
    }

    /// Expose the secret bytes as a slice.
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0 .0
    }
}

impl core::ops::Deref for DynamicRng {
    type Target = Dynamic<Vec<u8>>;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for DynamicRng {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::fmt::Debug for DynamicRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED_RANDOM]")
    }
}
