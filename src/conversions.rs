// ==========================================================================
// src/conversions.rs
// ==========================================================================
#[cfg(feature = "conversions")]
use alloc::string::String;
#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;
#[cfg(feature = "conversions")]
use zeroize::Zeroize;

/// Extension trait for safe, explicit conversions of secret byte data.
/// All methods require the caller to explicitly expose the secret first.
#[cfg(feature = "conversions")]
pub trait SecureConversionsExt {
    fn to_hex(&self) -> String;
    fn to_hex_upper(&self) -> String;
    fn to_base64url(&self) -> String;
    fn ct_eq(&self, other: &Self) -> bool;
}

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
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

#[cfg(feature = "conversions")]
impl<const N: usize> SecureConversionsExt for [u8; N] {
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
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self.as_slice(), other.as_slice()).into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexString — validated, lowercase hex wrapper
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(feature = "conversions")]
#[derive(Clone, Debug)]
pub struct HexString(crate::Dynamic<String>);

#[cfg(feature = "conversions")]
impl HexString {
    /// Creates a validated, lowercase hex string with **zero extra heap allocations**.
    ///
    /// Takes ownership of the input `String`. If validation fails, the input is
    /// zeroized immediately before returning the error (when the `zeroize` feature is enabled).
    pub fn new(mut s: String) -> Result<Self, &'static str> {
        // Fast early check – hex strings must have even length
        if s.len() % 2 != 0 {
            zeroize_input(&mut s);
            return Err("invalid hex string");
        }

        // Work directly on the underlying bytes – no copies
        let bytes = unsafe { s.as_mut_vec() };
        let mut valid = true;

        for b in bytes.iter_mut() {
            match *b {
                b'A'..=b'F' => *b += 32, // 'A' → 'a'
                b'a'..=b'f' | b'0'..=b'9' => {}
                _ => valid = false,
            }
        }

        if valid {
            Ok(Self(crate::Dynamic::new(s)))
        } else {
            zeroize_input(&mut s);
            Err("invalid hex string")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(self.0.expose_secret()).expect("HexString is always valid")
    }

    pub fn byte_len(&self) -> usize {
        self.0.expose_secret().len() / 2
    }
}

// Private helper – wipes rejected input when `zeroize` is enabled
#[cfg(feature = "conversions")]
#[inline(always)]
fn zeroize_input(s: &mut String) {
    #[cfg(feature = "zeroize")]
    {
        // SAFETY: String's internal buffer is valid for writes of its current length
        let vec = unsafe { s.as_mut_vec() };
        vec.zeroize();
    }
}

#[cfg(feature = "conversions")]
impl core::ops::Deref for HexString {
    type Target = crate::Dynamic<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(feature = "conversions", feature = "zeroize"))]
impl secrecy::ExposeSecret<String> for HexString {
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

// Manual constant-time equality
#[cfg(feature = "conversions")]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .expose_secret()
            .as_bytes()
            .ct_eq(other.0.expose_secret().as_bytes())
    }
}

#[cfg(feature = "conversions")]
impl Eq for HexString {}

// ─────────────────────────────────────────────────────────────────────────────
// RandomHex — only constructible from fresh RNG
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(all(feature = "rand", feature = "conversions"))]
#[derive(Clone, Debug)]
pub struct RandomHex(HexString);

#[cfg(all(feature = "rand", feature = "conversions"))]
impl RandomHex {
    pub(crate) fn new_fresh(hex: HexString) -> Self {
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
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(feature = "rand", feature = "conversions", feature = "zeroize"))]
impl secrecy::ExposeSecret<String> for RandomHex {
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl PartialEq for RandomHex {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl Eq for RandomHex {}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl<const N: usize> crate::rng::FixedRng<N> {
    pub fn random_hex() -> RandomHex {
        let hex = {
            let fresh_rng = Self::generate();
            hex::encode(fresh_rng.expose_secret())
        }; // fresh_rng dropped and zeroized here

        RandomHex::new_fresh(HexString(crate::Dynamic::new(hex)))
    }
}
