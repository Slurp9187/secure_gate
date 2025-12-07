// ==========================================================================
// src/macros.rs
// ==========================================================================

/// Creates a type alias for a fixed-size secure secret.
///
/// This macro generates a type alias to `Fixed<[u8; N]>` with optional visibility.
/// The generated type inherits all methods from `Fixed`, including `.expose_secret()`.
///
/// # Syntax
///
/// - `fixed_alias!(Name, size);` — public alias
/// - `fixed_alias!(vis Name, size);` — custom visibility (e.g., `pub(crate)`)
///
/// # Examples
///
/// Basic public alias:
/// ```
/// use secure_gate::fixed_alias;
/// fixed_alias!(Aes256Key, 32);
/// let key = Aes256Key::new([0u8; 32]);
/// assert_eq!(key.len(), 32);
/// ```
///
/// With custom visibility:
/// ```
/// use secure_gate::fixed_alias;
///
/// // crate-visible only
/// fixed_alias!(pub(crate) InternalKey, 64);
///
/// // visible only to the parent module (valid inside a module)
/// // fixed_alias!(pub(in super) ModuleKey, 16);
/// ```
///
/// `pub(in super)` and other path-based visibilities are fully supported
/// when used inside real modules, but cannot be demonstrated in top-level doc-tests.
///
/// The generated type is zero-cost and works with all features.
#[macro_export]
macro_rules! fixed_alias {
    // Full visibility control
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", $size, " bytes)")]
        $vis type $name = $crate::Fixed<[u8; $size]>;
    };
    // Convenience: default = pub
    ($name:ident, $size:literal) => {
        $crate::fixed_alias!(pub $name, $size);
    };
}

/// Creates a generic (const-sized) fixed secure buffer type.
///
/// This macro generates a type alias to `Fixed<[u8; N]>` with a custom doc string.
/// Useful for libraries providing generic secret buffers.
///
/// # Examples
///
/// With custom doc:
/// ```
/// use secure_gate::fixed_generic_alias;
/// fixed_generic_alias!(GenericKey, "Generic secure key buffer");
/// let key: GenericKey<32> = GenericKey::new([0u8; 32]);
/// ```
///
/// Default doc and visibility:
/// ```
/// use secure_gate::fixed_generic_alias;
/// fixed_generic_alias!(pub(crate) Buffer);
/// let buf: Buffer<16> = Buffer::new([0u8; 16]);
/// ```
#[macro_export]
macro_rules! fixed_generic_alias {
    ($vis:vis $name:ident, $doc:literal) => {
        #[doc = $doc]
        $vis type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
    ($name:ident, $doc:literal) => {
        $crate::fixed_generic_alias!(pub $name, $doc);
    };
    ($vis:vis $name:ident) => {
        #[doc = "Fixed-size secure byte buffer"]
        $vis type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
    ($name:ident) => {
        $crate::fixed_generic_alias!(pub $name);
    };
}

/// Creates a type alias for a random-only fixed-size secret.
///
/// This macro generates a type alias to `FixedRng<N>`, which can only be
/// instantiated via `.generate()` (requires the "rand" feature).
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::fixed_alias_rng;
/// fixed_alias_rng!(MasterKey, 32);
/// let key = MasterKey::generate();
/// assert_eq!(key.len(), 32);
/// # }
/// ```
#[macro_export]
macro_rules! fixed_alias_rng {
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", $size, " bytes)")]
        $vis type $name = $crate::rng::FixedRng<$size>;
    };
    ($name:ident, $size:literal) => {
        $crate::fixed_alias_rng!(pub $name, $size);
    };
}

/// Creates a type alias for a heap-allocated secure secret.
///
/// # Examples
///
/// ```
/// use secure_gate::dynamic_alias;
/// dynamic_alias!(Password, String);
/// let pw: Password = "hunter2".into();
/// assert_eq!(pw.expose_secret(), "hunter2");
/// ```
#[macro_export]
macro_rules! dynamic_alias {
    ($vis:vis $name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty) => {
        $crate::dynamic_alias!(pub $name, $inner);
    };
}

/// Creates a generic heap-allocated secure secret type alias.
///
/// # Examples
///
/// ```
/// use secure_gate::dynamic_generic_alias;
/// dynamic_generic_alias!(SecureVec, Vec<u8>, "Secure dynamic byte vector");
/// let vec = SecureVec::new(vec![1, 2, 3]);
/// assert_eq!(vec.len(), 3);
/// ```
#[macro_export]
macro_rules! dynamic_generic_alias {
    ($vis:vis $name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty, $doc:literal) => {
        $crate::dynamic_generic_alias!(pub $name, $inner, $doc);
    };
    ($vis:vis $name:ident, $inner:ty) => {
        $crate::dynamic_generic_alias!(
            $vis $name,
            $inner,
            concat!("Secure heap-allocated ", stringify!($inner))
        );
    };
    ($name:ident, $inner:ty) => {
        $crate::dynamic_generic_alias!(pub $name, $inner);
    };
}
