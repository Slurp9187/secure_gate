// src/dynamic.rs
//! Heap-allocated secure wrappers for dynamic secrets.
//!
//! `Dynamic<T>` is a zero-cost wrapper around `Box<T>` that:
//! - Prevents accidental cloning/leaking via `Debug` redaction
//! - Provides explicit `.expose_secret()` access (the canonical API)
//! - Supports idiomatic `.into()` conversion from owned values
//! - Works perfectly with `dynamic_alias!` for beautiful type aliases

use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

/// A zero-cost, heap-allocated wrapper for sensitive data.
///
/// See module docs for full examples.
pub struct Dynamic<T: ?Sized>(pub Box<T>);

impl<T: ?Sized> Dynamic<T> {
    #[inline(always)]
    pub fn new_boxed(value: Box<T>) -> Self {
        Dynamic(value)
    }

    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        Dynamic(value.into())
    }
}

impl<T: ?Sized> Deref for Dynamic<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for Dynamic<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: ?Sized> Dynamic<T> {
    /// Access the secret value immutably.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Dynamic;
    ///
    /// let pw: Dynamic<String> = "secret".into();
    /// assert_eq!(pw.expose_secret(), "secret");
    /// ```
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    #[deprecated(since = "0.5.5", note = "use `expose_secret` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view(&self) -> &T {
        self.expose_secret()
    }

    #[deprecated(since = "0.5.5", note = "use `expose_secret_mut` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }

    #[inline(always)]
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}

// Clone impls
#[cfg(not(feature = "zeroize"))]
impl<T: Clone> Clone for Dynamic<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + zeroize::Zeroize> Clone for Dynamic<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

impl Dynamic<String> {
    pub fn finish_mut(&mut self) -> &mut String {
        let s = &mut **self;
        s.shrink_to_fit();
        s
    }
}
impl Dynamic<Vec<u8>> {
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        let v = &mut **self;
        v.shrink_to_fit();
        v
    }
}

// ——— .into() ergonomics ———

/// Convert any owned value into a heap secret.
///
/// # Examples
///
/// ```
/// use secure_gate::Dynamic;
///
/// let pw: Dynamic<String> = "hunter2".into();
/// let data: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
///
/// assert_eq!(&*pw, "hunter2");
/// assert_eq!(data.expose_secret(), &[1, 2, 3]);
/// ```
impl<T> From<T> for Dynamic<T>
where
    T: Sized,
{
    #[inline(always)]
    fn from(value: T) -> Self {
        Self(Box::new(value))
    }
}

impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self(boxed)
    }
}

/// Convenience: `&str` → password secret.
///
/// ```
/// use secure_gate::Dynamic;
///
/// let pw: Dynamic<String> = "correct horse battery staple".into();
/// assert_eq!(&*pw, "correct horse battery staple");
/// ```
impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(s: &str) -> Self {
        Self(Box::new(s.to_string()))
    }
}
