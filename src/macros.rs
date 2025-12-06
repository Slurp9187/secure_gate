// src/macros.rs
//! secure-gate 0.6.0 — The Final Macro System (3×2 Matrix)
//! Pure type aliases only — all methods provided via blanket impls.

/// Concrete fixed-size secret (e.g. Aes256Key, Nonce24)
#[macro_export]
macro_rules! fixed_alias {
    ($name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", $size, " bytes)")]
        pub type $name = $crate::Fixed<[u8; $size]>;
    };
}

/// Generic fixed-size secret base (e.g. SecureSpan<24>)
#[macro_export]
macro_rules! fixed_generic_alias {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        pub type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
    ($name:ident) => {
        #[doc = "Fixed-size secure byte buffer"]
        pub type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
}

/// Fixed-size RNG-only secret
#[macro_export]
macro_rules! fixed_alias_rng {
    ($name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", $size, " bytes)")]
        pub type $name = $crate::rng::FixedRng<$size>;
    };
}

/// Concrete heap secret (e.g. Password, JwtKey)
#[macro_export]
macro_rules! dynamic_alias {
    ($name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        pub type $name = $crate::Dynamic<$inner>;
    };
}

/// Generic heap secret base
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

/// Dynamic RNG-only secret
#[macro_export]
macro_rules! dynamic_alias_rng {
    ($name:ident, $inner:ty) => {
        #[doc = concat!("Random-only heap secret (", stringify!($inner), ")")]
        pub type $name = $crate::rng::DynamicRng;
    };
}
