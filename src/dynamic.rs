// ==========================================================================
// src/dynamic.rs
// ==========================================================================

extern crate alloc;

use alloc::boxed::Box;

pub struct Dynamic<T: ?Sized>(Box<T>);

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

    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    #[inline(always)]
    pub fn into_inner(self) -> Box<T> {
        self.0
    }

    #[inline(always)]
    pub fn no_clone(self) -> crate::DynamicNoClone<T> {
        crate::DynamicNoClone::new(self.0)
    }
}

impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Clone + ?Sized> Clone for Dynamic<T> {
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
        let s = &mut *self.0;
        s.shrink_to_fit();
        s
    }
}

impl Dynamic<Vec<u8>> {
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        let v = &mut *self.0;
        v.shrink_to_fit();
        v
    }

    pub fn as_slice(&self) -> &[u8] {
        self.expose_secret()
    }
}

impl<T> From<T> for Dynamic<T> {
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

impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(s: &str) -> Self {
        Self(Box::new(s.to_string()))
    }
}

impl<T: PartialEq + ?Sized> PartialEq for Dynamic<T> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl<T: Eq + ?Sized> Eq for Dynamic<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}
