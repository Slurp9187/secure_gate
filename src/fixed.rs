// ==========================================================================
// src/fixed.rs
// ==========================================================================
use core::fmt;

/// Stack-allocated secure secret wrapper.
///
/// All access to the inner value requires an explicit `.expose_secret()` call.
/// No `Deref`, no `AsRef`, no hidden copies — every operation is loud and auditable.
pub struct Fixed<T>(T); // ← field is PRIVATE

impl<T> Fixed<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed(value)
    }

    /// Expose the secret for read-only access.
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Expose the secret for mutable access.
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Consume the wrapper and return the inner value.
    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Convert into a non-cloneable variant.
    #[inline(always)]
    pub fn no_clone(self) -> crate::FixedNoClone<T> {
        crate::FixedNoClone::new(self.0)
    }
}

// === Byte-array specific helpers ===
impl<const N: usize> Fixed<[u8; N]> {
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

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

// Debug is always redacted
impl<T> fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Explicit Clone only — no implicit Copy
impl<T: Clone> Clone for Fixed<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

// REMOVED: Copy impl for Fixed<[u8; N]>
// Implicit copying of secrets is a footgun — duplication must be intentional.

// Constant-time equality — only available with `conversions` feature
#[cfg(feature = "conversions")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Constant-time equality comparison.
    ///
    /// This is the **only safe way** to compare two fixed-size secrets.
    /// Available only when the `conversions` feature is enabled.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::conversions::SecureConversionsExt;
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

// Zeroize integration
#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}
