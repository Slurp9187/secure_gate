// src/zeroize.rs
//! Zeroizing wrappers that automatically wipe sensitive data on drop.
//!
//! This module is only compiled when the `zeroize` feature is enabled.
//!
//! ### Types
//!
//! | Type                     | Underlying implementation          | Access method                     | Notes |
//! |--------------------------|-------------------------------------|-----------------------------------|-------|
//! | `FixedZeroizing<T>`      | `zeroize::Zeroizing<T>` (re-export) | `&*value` or `.deref()`           | Stack-only, zero-cost |
//! | `DynamicZeroizing<T>`    | `secrecy::SecretBox<T>` wrapper     | `.expose_secret()` / `.expose_secret_mut()` | Heap-only, prevents cloning |
//!
//! Both types implement `ZeroizeOnDrop` and wipe the contained secret
//! (including spare capacity for `Vec<u8>`/`String`) when dropped.
//!
//! # Examples
//!
//! ```
//! use secure_gate::{DynamicZeroizing, FixedZeroizing};
//! use secrecy::ExposeSecret;
//!
//! // Fixed-size zeroizing secret
//! let key = FixedZeroizing::new([42u8; 32]);
//! assert_eq!(key[..], [42u8; 32]);
//! drop(key); // memory is zeroed here
//!
//! // Heap-allocated zeroizing secret
//! let pw: DynamicZeroizing<String> = "hunter2".into();
//! assert_eq!(pw.expose_secret(), "hunter2");
//! drop(pw); // both used bytes and spare capacity are zeroed
//! ```

#[cfg(feature = "zeroize")]
use zeroize::{DefaultIsZeroes, Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, SecretBox};

#[cfg(feature = "zeroize")]
/// Re-export of `zeroize::Zeroizing<T>` for stack-allocated secrets.
///
/// This is the canonical zeroizing wrapper for fixed-size data.
pub type FixedNoClone<T> = Zeroizing<T>;

#[cfg(feature = "zeroize")]
/// Zeroizing wrapper for heap-allocated secrets.
///
/// Uses `secrecy::SecretBox<T>` internally to prevent accidental cloning
/// while still providing zeroization of the full allocation (including spare capacity).
pub struct DynamicNoClone<T: ?Sized + Zeroize>(SecretBox<T>);

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> DynamicNoClone<T> {
    /// Creates a new `DynamicZeroizing` from a boxed value.
    ///
    /// The boxed value will be zeroed (including spare capacity) on drop.
    #[inline(always)]
    pub fn new(value: Box<T>) -> Self {
        Self(SecretBox::new(value))
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> core::fmt::Debug for DynamicNoClone<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(feature = "zeroize")]
impl<S: ?Sized + Zeroize> ExposeSecret<S> for DynamicNoClone<S> {
    #[inline(always)]
    fn expose_secret(&self) -> &S {
        self.0.expose_secret()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + DefaultIsZeroes> Zeroize for DynamicNoClone<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for DynamicNoClone<T> {}

/// Convenience conversions from non-zeroizing wrappers.
#[cfg(feature = "zeroize")]
impl<T: Zeroize> From<crate::Fixed<T>> for FixedNoClone<T> {
    #[inline(always)]
    fn from(fixed: crate::Fixed<T>) -> Self {
        Zeroizing::new(fixed.0)
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> From<crate::Dynamic<T>> for DynamicNoClone<T> {
    #[inline(always)]
    fn from(dynamic: crate::Dynamic<T>) -> Self {
        Self(SecretBox::new(dynamic.0))
    }
}

/// Zeroize impls for the non-zeroizing wrappers when the `zeroize` feature is active.
#[cfg(feature = "zeroize")]
impl<T: Zeroize> Zeroize for crate::Fixed<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + DefaultIsZeroes> Zeroize for crate::Dynamic<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize> ZeroizeOnDrop for crate::Fixed<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for crate::Dynamic<T> {}

/// Ergonomic `.into()` support for zeroizing heap secrets.
#[cfg(feature = "zeroize")]
impl<T: Zeroize + Send + 'static> From<T> for DynamicNoClone<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self::new(Box::new(value))
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + DefaultIsZeroes + Send + 'static> From<Box<T>> for DynamicNoClone<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self::new(boxed)
    }
}

#[cfg(feature = "zeroize")]
impl From<&str> for DynamicNoClone<String> {
    #[inline(always)]
    fn from(s: &str) -> Self {
        Self::new(Box::new(s.to_string()))
    }
}
