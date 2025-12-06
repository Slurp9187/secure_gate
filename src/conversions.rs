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

#[cfg(feature = "conversions")]
use alloc::string::String;

#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;

#[cfg(all(feature = "rand", feature = "conversions"))]
use secrecy::ExposeSecret;

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

// ───── Compile-time safety net ─────
#[cfg(feature = "conversions")]
trait _AssertNoImplForFixed {}
#[cfg(feature = "conversions")]
impl<T> _AssertNoImplForFixed for T where T: SecureConversionsExt {}

#[cfg(feature = "conversions")]
impl<const N: usize> _AssertNoImplForFixed for crate::Fixed<[u8; N]> {}

// ───── New: HexString newtype ─────
#[cfg(feature = "conversions")]
#[derive(Clone, Debug, PartialEq)]
pub struct HexString(crate::Dynamic<String>);

#[cfg(feature = "conversions")]
impl HexString {
    pub fn new(s: String) -> Result<Self, &'static str> {
        let lower = s.to_lowercase();
        if lower.len() % 2 != 0 || !lower.chars().all(|c| c.is_ascii_hexdigit()) {
            Err("Invalid hex: must be even length with 0-9a-fA-F chars")
        } else {
            Ok(Self(crate::Dynamic::new(lower)))
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(self.expose_secret()).expect("Validated hex")
    }

    pub fn byte_len(&self) -> usize {
        self.expose_secret().len() / 2
    }
}

#[cfg(feature = "conversions")]
impl core::ops::Deref for HexString {
    type Target = crate::Dynamic<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "conversions")]
impl ExposeSecret<String> for HexString {
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

// ───── New: RandomHex newtype ─────
#[cfg(all(feature = "rand", feature = "conversions"))]
#[derive(Clone, Debug, PartialEq)]
pub struct RandomHex(pub HexString);

#[cfg(all(feature = "rand", feature = "conversions"))]
impl RandomHex {
    pub fn new(hex: HexString) -> Self {
        Self(hex)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn byte_len(&self) -> usize {
        self.0.byte_len()
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl core::ops::Deref for RandomHex {
    type Target = HexString;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl ExposeSecret<String> for RandomHex {
    #[inline(always)]
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

// src/conversions.rs — add this block (replaces your current one)
#[cfg(all(feature = "rand", feature = "conversions"))]
impl<const N: usize> crate::rng::FixedRng<N> {
    /// Generate a fresh random key of this size and return it as a validated `RandomHex`.
    ///
    /// This is a **static method** — call it directly on the type:
    ///
    /// ```
    /// fixed_alias_rng!(Aes256Key, 32);
    /// let hex = Aes256Key::random_hex();  // Works perfectly!
    /// ```
    #[inline(always)]
    pub fn random_hex() -> RandomHex {
        let rng = Self::rng(); // generates fresh random bytes
        let hex_str = rng.expose_secret().to_hex();
        let hex_string =
            HexString::new(hex_str).expect("hex::encode always produces valid lowercase hex");
        RandomHex::new(hex_string)
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_works_with_alias() {
    use crate::fixed_alias_rng;

    fixed_alias_rng!(HexKey, 32);

    let hex: RandomHex = HexKey::random_hex();

    assert_eq!(hex.expose_secret().len(), 64); // 32 bytes → 64 hex chars
    assert!(hex.expose_secret().chars().all(|c| c.is_ascii_hexdigit()));

    let bytes_back = hex.to_bytes();
    assert_eq!(bytes_back.len(), 32);
}
