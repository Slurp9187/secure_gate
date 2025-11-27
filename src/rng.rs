// src/rng.rs

use rand::{rngs::OsRng, TryRngCore};
use std::cell::RefCell;

thread_local! {
    static OS_RNG: RefCell<OsRng> = const { RefCell::new(OsRng) };
}

/// Extension trait for cryptographically secure random generation of fixed-size secrets.
pub trait SecureRandomExt {
    /// Generate a new random instance using the operating system's cryptographically
    /// secure PRNG.
    ///
    /// Panics if the OS RNG fails (extremely rare, considered fatal in crypto code).
    fn random() -> Self;
}

impl<const N: usize> SecureRandomExt for crate::Fixed<[u8; N]> {
    #[inline(always)]
    fn random() -> Self {
        OS_RNG.with(|rng| {
            let mut rng = rng.borrow_mut();
            let mut bytes = [0u8; N];
            rng.try_fill_bytes(&mut bytes)
                .expect("OsRng failed to fill bytes — this should never happen");
            Self::new(bytes)
        })
    }
}
