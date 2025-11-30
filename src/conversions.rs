// src/conversions.rs
//! Optional ergonomic conversions for fixed-size byte secrets
//!
//! This module provides the [`SecureConversionsExt`] trait, which adds common
//! conversion methods (hex, Base64URL, constant-time equality) to all
//! `Fixed<[u8; N]>` types and `fixed_alias!` types.
//!
//! Enabled only when the `conversions` feature is activated — zero impact otherwise.
//!
//! # Examples
//!
//! ```
//! use secure_gate::{fixed_alias, SecureConversionsExt};
//!
//! #[cfg(feature = "rand")]
//! use secure_gate::SecureRandomExt;
//!
//! fixed_alias!(Aes256Key, 32);
//!
//! #[cfg(feature = "rand")]
//! let key = Aes256Key::random();  // requires `rand` feature
//! #[cfg(not(feature = "rand"))]
//! let key = Aes256Key::from([0u8; 32]); // fallback for docs
//!
//! let hex = key.to_hex();         // "00010203..."
//! let b64 = key.to_base64url();   // "AAECAwQFBg..."
//! assert!(key.ct_eq(&key));
//! ```

#[cfg(feature = "conversions")]
use alloc::string::String;

#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;

/// Extension trait for common secure conversions
///
/// Adds `.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, and `.ct_eq()`
/// to all fixed-size byte secrets.
pub trait SecureConversionsExt {
    /// Convert to lowercase hex string
    fn to_hex(&self) -> String;

    /// Convert to uppercase hex string
    fn to_hex_upper(&self) -> String;

    /// Convert to Base64URL (no padding) — ideal for JSON export and URLs
    fn to_base64url(&self) -> String;

    /// Constant-time equality comparison
    ///
    /// Use this instead of `==` for secrets — prevents timing attacks.
    fn ct_eq(&self, other: &Self) -> bool;
}

#[cfg(feature = "conversions")]
impl<const N: usize> SecureConversionsExt for crate::Fixed<[u8; N]> {
    #[inline]
    fn to_hex(&self) -> String {
        hex::encode(self.expose_secret())
    }

    #[inline]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self.expose_secret())
    }

    #[inline]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.expose_secret())
    }

    #[inline]
    fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.expose_secret().ct_eq(other.expose_secret()).into()
    }
}
