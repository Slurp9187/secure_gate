// tests/integration.rs (add to the bottom)

#[cfg(feature = "rand")]
#[test]
fn random_generates_different_values() {
    use secure_gate::{fixed_alias, SecureRandomExt};

    fixed_alias!(TestKey32, 32);
    fixed_alias!(TestKey16, 16);

    // Generate two keys — they must be different (probability of collision: 2^256 or 2^128)
    let key1 = TestKey32::random();
    let key2 = TestKey32::random();

    assert_ne!(key1.expose_secret(), key2.expose_secret());
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);

    // Also test a different size
    let nonce1 = TestKey16::random();
    let nonce2 = TestKey16::random();

    assert_ne!(nonce1.expose_secret(), nonce2.expose_secret());
    assert_eq!(nonce1.len(), 16);

    // Bonus: sanity-check that it's not all zeros (extremely unlikely, but catches broken RNG)
    assert_ne!(*key1.expose_secret(), [0u8; 32]);
    assert_ne!(*nonce1.expose_secret(), [0u8; 16]);
}
