// src/serde.rs
//! Optional Serde integration for `secure-gate` types.
//!
//! This module is only available when the `serde` feature is enabled.
//!
//! ### Behavior summary
//!
//! | Type            | Serialize | Deserialize                          | Reason |
//! |-----------------|-----------|--------------------------------------|--------|
//! | `Fixed<T>`      | Yes       | Yes (transparent)                    | Fixed-size, safe to round-trip |
//! | `Dynamic<T>`    | Yes       | **Intentionally disabled**          | Prevents accidental loading of secrets from untrusted input |
//!
//! ### Recommended pattern
//!
//! Always deserialize into the inner type first, then wrap manually:
//!
//! ```
//! use secure_gate::Dynamic;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! struct Config {
//!     api_key: String,
//! }
//!
//! let json = r#"{ "api_key": "super-secret" }"#;
//! let config: Config = serde_json::from_str(json).unwrap();
//! let secret_key: Dynamic<String> = Dynamic::new(config.api_key); // now securely wrapped
//! assert_eq!(secret_key.expose_secret(), "super-secret");
//! ```
//!
//! # Examples
//!
//! ```
//! use secure_gate::{Dynamic, Fixed};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, Debug)]
//! struct Message {
//!     nonce: Fixed<[u8; 12]>,
//!     password: Dynamic<String>,
//! }
//!
//! let msg = Message {
//!     nonce: [42u8; 12].into(),
//!     password: "hunter2".into(),
//! };
//!
//! let json = serde_json::to_string(&msg).unwrap();
//! assert!(json.contains("hunter2"));
//!
//! // Deserialization of `Dynamic<String>` fails with a clear error
//! let err = serde_json::from_str::<Message>(&json).unwrap_err();
//! assert!(err.to_string().contains("intentionally disabled"));
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::{Dynamic, Fixed};

/// Serializes a `Fixed<T>` exactly like the inner `T`.
#[cfg(feature = "serde")]
impl<T: Serialize> Serialize for Fixed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Deserializes a `Fixed<T>` transparently from the inner `T`.
#[cfg(feature = "serde")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Fixed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Fixed)
    }
}

/// Serializes a `Dynamic<T>` exactly like the inner `T`.
#[cfg(feature = "serde")]
impl<T: ?Sized + Serialize> Serialize for Dynamic<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

/// Deserialization of `Dynamic<T>` is intentionally disabled.
///
/// # Security Rationale
///
/// Automatically deserializing secrets from untrusted input is a common source
/// of bugs and potential side-channel leaks. You should always deserialize
/// into the plain inner type first, validate it, and then wrap it explicitly
/// with `Dynamic::new(...)`.
#[cfg(feature = "serde")]
impl<'de, T: ?Sized> Deserialize<'de> for Dynamic<T> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "Deserialization of Dynamic<T> is intentionally disabled for security reasons.\n\
             Secrets should never be automatically loaded from untrusted input.\n\
             Instead, deserialize into the inner type first, then wrap with Dynamic::new().",
        ))
    }
}
