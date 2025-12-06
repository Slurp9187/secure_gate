// ==========================================================================
// src/no_clone.rs
// ==========================================================================

extern crate alloc;
use alloc::boxed::Box;
use core::fmt;

pub struct FixedNoClone<T>(T);

pub struct DynamicNoClone<T: ?Sized>(Box<T>);

impl<T> FixedNoClone<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        FixedNoClone(value)
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
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: ?Sized> DynamicNoClone<T> {
    #[inline(always)]
    pub fn new(value: Box<T>) -> Self {
        DynamicNoClone(value)
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
}

impl<T> fmt::Debug for FixedNoClone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED_NO_CLONE]")
    }
}

impl<T: ?Sized> fmt::Debug for DynamicNoClone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED_NO_CLONE]")
    }
}

impl DynamicNoClone<String> {
    pub fn finish_mut(&mut self) -> &mut String {
        let s = &mut *self.0;
        s.shrink_to_fit();
        s
    }
}

impl DynamicNoClone<Vec<u8>> {
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        let v = &mut *self.0;
        v.shrink_to_fit();
        v
    }

    pub fn as_slice(&self) -> &[u8] {
        self.expose_secret()
    }
}

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "zeroize")]
impl<T: Zeroize> Zeroize for FixedNoClone<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> Zeroize for DynamicNoClone<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize> ZeroizeOnDrop for FixedNoClone<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for DynamicNoClone<T> {}
