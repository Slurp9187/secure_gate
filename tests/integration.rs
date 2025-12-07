// ==========================================================================
// tests/integration.rs
// ==========================================================================
// Core integration tests — pure v0.6.0 API

use secure_gate::{Dynamic, Fixed};

#[test]
fn basic_usage_explicit_access() {
    let mut key = Fixed::new([0u8; 32]);
    let mut pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(key.len(), 32);
    assert!(!key.is_empty());
    assert_eq!(pw.expose_secret().len(), 7);
    assert_eq!(pw.expose_secret(), "hunter2");

    pw.expose_secret_mut().push('!');
    key.expose_secret_mut()[0] = 1;

    assert_eq!(pw.expose_secret(), "hunter2!");
    assert_eq!(key.expose_secret()[0], 1); // ← fixed: proper assert_eq!
}

#[test]
fn fixed_is_truly_zero_cost() {
    let key = Fixed::new([0u8; 32]);
    assert_eq!(core::mem::size_of_val(&key), 32);
}

#[test]
fn debug_is_redacted() {
    let key = Fixed::new([0u8; 32]);
    let pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(format!("{key:?}"), "[REDACTED]");
    assert_eq!(format!("{pw:?}"), "[REDACTED]");
    assert_eq!(format!("{key:#?}"), "[REDACTED]");
    assert_eq!(format!("{pw:#?}"), "[REDACTED]");
}

#[test]
fn clone_dynamic_is_isolated() {
    let pw1 = Dynamic::<String>::new("original".to_string());
    let pw2 = pw1.clone();

    let mut pw1_mut = pw1.clone();
    pw1_mut.expose_secret_mut().push('!');

    assert_eq!(pw1.expose_secret(), "original");
    assert_eq!(pw2.expose_secret(), "original");
    assert_eq!(pw1_mut.expose_secret(), "original!");
}

#[test]
fn into_inner_extracts() {
    let key = Fixed::new([1u8; 32]);
    assert_eq!(key.into_inner(), [1u8; 32]);

    let pw = Dynamic::<String>::new("secret".to_string());
    let boxed = pw.into_inner();
    assert_eq!(&*boxed, "secret");
}

#[test]
fn explicit_access_for_byte_arrays() {
    let mut key = Fixed::new([42u8; 32]);

    let slice: &[u8] = key.expose_secret();
    assert_eq!(slice.len(), 32);
    assert_eq!(slice[0], 42);

    let mut_slice: &mut [u8] = key.expose_secret_mut();
    mut_slice[0] = 99;
    assert_eq!(key.expose_secret()[0], 99);
}
