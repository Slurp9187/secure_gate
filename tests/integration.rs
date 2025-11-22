// tests/integration.rs
// Final test suite — proves everything works

use secure_gate::{dynamic_alias, fixed_alias, secure, Dynamic, Fixed};

#[test]
fn basic_usage_and_deref() {
    let mut key = Fixed::new([0u8; 32]);
    let mut pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(key.len(), 32);
    assert_eq!(pw.len(), 7);
    assert_eq!(&*pw, "hunter2");

    pw.push('!');
    key[0] = 1;

    assert_eq!(&*pw, "hunter2!");
    assert_eq!(key[0], 1);

    let s: &str = &pw;
    assert_eq!(s, "hunter2!");
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

    let key_debug = format!("{key:?}");
    let pw_debug = format!("{pw:?}");

    assert_eq!(key_debug, "[REDACTED]");
    assert_eq!(pw_debug, "[REDACTED]");

    let key_pretty = format!("{key:#?}");
    let pw_pretty = format!("{pw:#?}");

    assert_eq!(key_pretty, "[REDACTED]");
    assert_eq!(pw_pretty, "[REDACTED]");
}

#[test]
fn clone_dynamic_is_isolated() {
    let pw1 = Dynamic::<String>::new("original".to_string());
    let pw2 = pw1.clone();

    let mut pw1_mut = pw1.clone();
    pw1_mut.push('!');

    assert_eq!(&*pw1, "original");
    assert_eq!(&*pw2, "original");
    assert_eq!(&*pw1_mut, "original!");
}

#[test]
fn into_inner_extracts() {
    let key = Fixed::new([1u8; 32]);
    assert_eq!(key.into_inner(), [1u8; 32]);

    let pw = Dynamic::<String>::new("secret".to_string());
    let boxed = pw.into_inner();
    assert_eq!(&*boxed, "secret");
}

#[cfg(feature = "serde")]
#[test]
fn serde_roundtrip_fixed() {
    fixed_alias!(SerdeKey, 32);
    let key = SerdeKey::new([42u8; 32]);
    let json = serde_json::to_string(&key).unwrap();
    let key2: SerdeKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key.0, key2.0);
}

#[cfg(feature = "serde")]
#[test]
fn serde_dynamic_serializes() {
    let pw = Dynamic::<String>::new("hunter2".to_string());
    let json = serde_json::to_string(&pw).unwrap();
    assert_eq!(json, "\"hunter2\"");
}

#[test]
fn dynamic_alias_works() {
    dynamic_alias!(Password, String);
    let mut pw: Password = Dynamic::new("hunter2".to_string());
    assert_eq!(pw.len(), 7);
    pw.push('!');
    assert_eq!(&*pw, "hunter2!");
}

#[test]
fn fixed_alias_works() {
    fixed_alias!(MyKey, 32);
    let k1: MyKey = [42u8; 32].into();
    let k2 = MyKey::new([42u8; 32]);
    assert_eq!(k1.0, k2.0);

    let iv = secure!([u8; 16], [1u8; 16]);
    assert_eq!(iv.0, [1u8; 16]);
}

#[cfg(feature = "serde")]
#[test]
fn dynamic_deserialize_is_blocked_with_clear_error() {
    use serde::Deserialize;

    // Try to deserialize directly — should fail to compile
    // But we test the runtime error message via a helper type
    #[derive(Deserialize, Debug)] // ← added Debug
    struct Wrapper {
        #[allow(dead_code)]
        secret: Dynamic<String>,
    }

    let json = r#"{"secret": "hunter2"}"#;

    let err = serde_json::from_str::<Wrapper>(json).expect_err("Deserialization should fail");

    let msg = err.to_string();
    assert!(
        msg.contains("Deserialization of Dynamic<T> is intentionally disabled")
            || msg.contains("Dynamic<T> is intentionally disabled"),
        "Error message should explain security rationale. Got: {msg}"
    );
}

#[cfg(feature = "serde")]
#[test]
fn fixed_can_be_deserialized() {
    fixed_alias!(Key32, 32);

    // Proper JSON array of 32 zeros
    let json = r#"[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"#;

    let key: Key32 = serde_json::from_str(json).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(key.0, [0u8; 32]);
}
