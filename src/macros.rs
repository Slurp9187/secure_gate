// src/macros.rs
//! Ergonomic macros for creating secure secret aliases.
//!
//! - `fixed_alias!` → alias for `Fixed<[u8; N]>`
//! - `fixed_alias_rng!` → alias for `FixedRng<N>` (random-only)
//! - `dynamic_alias!` → alias for `Dynamic<T>`
//! - `dynamic_alias_rng!` → alias for `DynamicRng` (random-only)

#[macro_export]
macro_rules! fixed_alias {
    ($name:ident, $size:literal) => {
        /// Fixed-size secret of exactly `$size` bytes.
        pub type $name = $crate::Fixed<[u8; $size]>;
    };
}

#[macro_export]
macro_rules! fixed_generic_alias {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        pub type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
    ($name:ident) => {
        #[doc = "Fixed-size secure byte buffer (zero-cost wrapper around secure_gate::Fixed)"]
        pub type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
}

/// Creates a type alias for a **random-only** fixed-size secret.
///
/// Usage:
/// ```
/// use secure_gate::fixed_alias_rng;
///
/// fixed_alias_rng!(Aes256Key, 32);
///
/// let key = Aes256Key::rng();  // generates fresh random key
/// ```
#[macro_export]
macro_rules! fixed_alias_rng {
    ($name:ident, $size:literal) => {
        /// Random-only fixed-size secret (`FixedRng<$size>`).
        ///
        /// Construct using `.rng()` — this is the only way to create it.
        pub type $name = $crate::rng::FixedRng<$size>;
    };
}

#[macro_export]
macro_rules! dynamic_alias {
    ($name:ident, $ty:ty) => {
        /// Heap-allocated secure secret.
        pub type $name = $crate::Dynamic<$ty>;
    };
}

#[macro_export]
macro_rules! dynamic_generic_alias {
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        pub type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty) => {
        $crate::dynamic_generic_alias!(
            $name,
            $inner,
            concat!("Secure heap-allocated ", stringify!($inner))
        );
    };
}

/// Creates a type alias for a **random-only** dynamic secret.
///
/// Usage:
/// ```
/// use secure_gate::dynamic_alias_rng;
///
/// dynamic_alias_rng!(Salt, Vec<u8>);
///
/// let salt = Salt::rng(32);
/// ```
#[macro_export]
macro_rules! dynamic_alias_rng {
    ($name:ident) => {
        /// Random-only dynamic secret (`DynamicRng`).
        ///
        /// Construct using `.rng(len)` — this is the only way to create it.
        pub type $name = $crate::rng::DynamicRng;
    };
}
