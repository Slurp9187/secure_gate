// src/conversions.rs
//! Ergonomic conversions for fixed-size secrets — **explicit exposure required**
//!
//! This module provides the [`SecureConversionsExt`] trait containing `.to_hex()`,
//! `.to_hex_upper()`, `.to_base64url()`, and `.ct_eq()`.
//!
//! The trait is implemented **only on `&[u8]`**, meaning you **must** call
//! `.expose_secret()` first. This guarantees every conversion site is loud,
//! intentional, and visible in code reviews.
//!
//! Enabled via the `conversions` feature (zero impact when disabled).
//!
//! # Correct usage (v0.5.9+)
//!
//! ```
//! use secure_gate::{fixed_alias, SecureConversionsExt};
//!
//! fixed_alias!(Aes256Key, 32);
//!
//! let key1 = Aes256Key::from([0x42; 32]);
//! let key2 = Aes256Key::from([0x42; 32]);
//!
//! let hex = key1.expose_secret().to_hex();
//! let b64 = key1.expose_secret().to_base64url();
//! assert!(key1.expose_secret().ct_eq(key2.expose_secret()));
//! ```

#[cfg(feature = "conversions")]
use alloc::string::String;

#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;

// Loud deprecation bomb — impossible to miss if someone uses the old API
#[cfg(all(feature = "conversions", not(doc)))]
#[deprecated(
    since = "0.5.9",
    note = "DIRECT CONVERSIONS BYPASS expose_secret() — USE .expose_secret().to_hex() ETC."
)]
#[doc(hidden)]
const _DIRECT_CONVERSIONS_ARE_EVIL: () = ();

/// Extension trait for common secure conversions.
///
/// # Security
///
/// This trait is **intentionally** only implemented for `&[u8]`.
/// There is **no** impl for `Fixed<T>` — this guarantees every conversion
/// requires an explicit `.expose_secret()` call.
pub trait SecureConversionsExt {
    fn to_hex(&self) -> String;
    fn to_hex_upper(&self) -> String;
    fn to_base64url(&self) -> String;
    fn ct_eq(&self, other: &Self) -> bool;
}

/// Core implementation — only on already-exposed bytes
#[cfg(feature = "conversions")]
impl SecureConversionsExt for [u8] {
    #[inline]
    fn to_hex(&self) -> String {
        hex::encode(self)
    }

    #[inline]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }

    #[inline]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }

    #[inline]
    fn ct_eq(&self, other: &[u8]) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

/// Backward-compatibility shims — **deprecated**
///
/// Will be removed in v0.6.0.
#[cfg(feature = "conversions")]
impl<const N: usize> crate::Fixed<[u8; N]> {
    #[deprecated(
        since = "0.5.9",
        note = "use `expose_secret().to_hex()` instead — makes secret exposure explicit"
    )]
    #[doc(hidden)]
    #[inline(always)]
    pub fn to_hex(&self) -> String {
        self.expose_secret().to_hex()
    }

    #[deprecated(since = "0.5.9", note = "use `expose_secret().to_hex_upper()` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn to_hex_upper(&self) -> String {
        self.expose_secret().to_hex_upper()
    }

    #[deprecated(since = "0.5.9", note = "use `expose_secret().to_base64url()` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn to_base64url(&self) -> String {
        self.expose_secret().to_base64url()
    }

    #[deprecated(
        since = "0.5.9",
        note = "use `expose_secret().ct_eq(other.expose_secret())` instead"
    )]
    #[doc(hidden)]
    #[inline(always)]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

// ───── Compile-time safety net — prevents accidental re-introduction of the bad impl ─────
//
// We use a negative impl to trigger a compile error if someone adds an impl of
// SecureConversionsExt for Fixed<[u8; N]> in the future.
//
// This is a well-known Rust pattern (used by crates like `serde`, `thiserror`, etc.)
// to enforce API invariants at compile time.

#[cfg(feature = "conversions")]
trait _AssertNoImplForFixed {}
#[cfg(feature = "conversions")]
impl<T> _AssertNoImplForFixed for T where T: SecureConversionsExt {}

#[cfg(feature = "conversions")]
impl<const N: usize> _AssertNoImplForFixed for crate::Fixed<[u8; N]> {
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //  If anyone ever adds `impl SecureConversionsExt for Fixed<[u8; N]>`, this line
    //  will cause a compile error: "conflicting implementation"
    //  → immediate, loud failure instead of silent security regression
}
