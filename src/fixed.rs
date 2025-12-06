// src/fixed.rs
use core::fmt;
use core::ops::{Deref, DerefMut};

pub struct Fixed<T>(pub T);

impl<T> Fixed<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed(value)
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

    #[inline(always)]
    pub fn no_clone(self) -> crate::FixedNoClone<T> {
        crate::FixedNoClone::new(self.0)
    }
}

impl<T> Deref for Fixed<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Fixed<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<const N: usize> Fixed<[u8; N]> {
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "slice length mismatch");
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes[..N]);
        Self::new(arr)
    }
}

impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

impl<const N: usize> AsRef<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.expose_secret()
    }
}

impl<const N: usize> AsMut<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        self.expose_secret_mut()
    }
}

impl<T> fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Clone> Clone for Fixed<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const N: usize> Copy for Fixed<[u8; N]> where [u8; N]: Copy {}

#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}
