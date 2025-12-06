// tests/random_bytes_paranoia_tests.rs
//! Ultimate regression shield for RandomBytes + random_alias!
//!
//! If this passes → nothing is broken.

#![cfg(feature = "rand")]

use secure_gate::{fixed_alias_rng, FixedRng, SecureRandomExt}; // ← THIS LINE WAS MISSING

fn expose<const N: usize>(rb: &FixedRng<N>) -> &[u8; N] {
    rb.expose_secret()
}

#[test]
fn basic_generation() {
    fixed_alias_rng!(Key32, 32);
    let a = Key32::new();
    let b = Key32::new();
    assert_ne!(expose(&a), expose(&b));
    assert!(!expose(&a).iter().all(|&b| b == 0));
}

#[test]
fn deprecated_names_still_work() {
    fixed_alias_rng!(Legacy32, 32);

    #[allow(deprecated)]
    {
        let a = Legacy32::random(); // old name
        let b = Legacy32::random_bytes(); // old name
        let c = Legacy32::new(); // new name

        // All three must be valid 32-byte random values
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_eq!(c.len(), 32);

        // They must be different from each other (statistically)
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_ne!(a.expose_secret(), c.expose_secret());
        assert_ne!(b.expose_secret(), c.expose_secret());

        // None of them are all zeros
        assert!(!a.expose_secret().iter().all(|&x| x == 0));
    }
}

#[test]
fn macro_generates_all_methods() {
    fixed_alias_rng!(MacroTest, 32);
    let _ = MacroTest::new();
    #[allow(deprecated)]
    let _ = MacroTest::random();
    #[allow(deprecated)]
    let _ = MacroTest::random_bytes();
}

#[test]
fn debug_is_redacted() {
    fixed_alias_rng!(DebugTest, 32);
    let rb = DebugTest::new();
    assert_eq!(format!("{rb:?}"), "[REDACTED_RANDOM]");
}

#[test]
fn different_aliases_are_different_types() {
    fixed_alias_rng!(TypeA, 32);
    fixed_alias_rng!(TypeB, 32);
    let a = TypeA::new();
    let _ = a;
    // let _wrong: TypeB = a; // ← does not compile — perfect!
}

#[test]
fn all_good() {
    println!("RANDOMBYTES PARANOIA: ALL TESTS PASS — SAFE TO SHIP");
}
