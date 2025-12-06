// src/fixed.rs
//! Stack-allocated, zero-cost secure wrappers for fixed-size secrets.
//!
//! `Fixed<T>` is a transparent wrapper around any type `T` that lives entirely on the stack.
//! It provides:
//! - Zero-cost abstraction via `Deref`/`DerefMut`.
//! - Automatic redaction in `Debug` output.
//! - Explicit access via `.expose_secret()` (canonical API).
//! - Specialized ergonomics for `[u8; N]` arrays (e.g., crypto keys, nonces).
//!
//! # v0.6.0 — `.no_clone()`
//!
//! Use `.no_clone()` to convert a `Fixed<T>` into a `FixedNoClone<T>` — a type that
//! **cannot be cloned or copied under any circumstances**.
//!
//! ```
//! fixed_alias!(MasterKey, 32);
//!
//! let session_key = MasterKey::new(rng.gen());           // Clone allowed (rare)
//! let master_key  = MasterKey::no_clone(rng.gen());     // Clone **impossible**
//! // master_key.clone(); // ← hard compile error
//! ```

use core::convert::From;
use core::ops::{Deref, DerefMut};

/// A zero-cost, stack-allocated wrapper for sensitive data.
pub struct Fixed<T>(pub T);

impl<T> Fixed<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed(value)
    }

    /// Convert this `Fixed<T>` into a **non-cloneable** version.
    ///
    /// Returns `FixedNoClone<T>` — compiler-enforced **never** `Clone` or `Copy`.
    ///
    /// Use for master keys, HSM seeds, root passwords — anything that must exist
    /// in **exactly one place in memory**.
    ///
    /// ```compile_fail
    /// let root = Aes256Key::new(rng.gen()).no_clone();
    /// root.clone(); // ← error: `FixedNoClone<...>` does not implement `Clone`
    /// ```
    #[inline(always)]
    pub fn no_clone(self) -> crate::FixedNoClone<T> {
        crate::FixedNoClone::new(self.0)
    }
}

impl<T> Deref for Fixed<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Fixed<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// ───── [u8; N] helpers ─────

impl<const N: usize> Fixed<[u8; N]> {
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "slice length mismatch");
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes[..N]);
        Self::new(arr)
    }
}

impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

impl<const N: usize> AsRef<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<T> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> Fixed<T> {
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    #[deprecated(since = "0.5.5", note = "use `expose_secret` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view(&self) -> &T {
        self.expose_secret()
    }

    #[deprecated(since = "0.5.5", note = "use `expose_secret_mut` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }

    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

// ───── Optional traits ─────

impl<T: Clone> Clone for Fixed<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const N: usize> Copy for Fixed<[u8; N]> where [u8; N]: Copy {}
