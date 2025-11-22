```rust
// tests/integration.rs
// Final test suite — proves everything works

use secure_gate_0_5_0::{dynamic_alias, fixed_alias, secure, Dynamic, Fixed};

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
fn macros_work_perfectly() {
    // fixed_alias! for fixed-size
    fixed_alias!(MyKey, 32);
    let k1: MyKey = [42u8; 32].into();
    let k2 = MyKey::new([42u8; 32]);
    assert_eq!(k1.0, k2.0);

    // dynamic_alias! for dynamic
    dynamic_alias!(Password, String);
    let pw: Password = Dynamic::new("hunter2".to_string());
    assert_eq!(pw.len(), 7);

    // secure! macro
    let iv = secure!([u8; 16], [1u8; 16]);
    assert_eq!(iv.0, [1u8; 16]);
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

#[cfg(feature = "zeroize")]
#[test]
fn zeroize_on_drop_wipes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WIPED: AtomicBool = AtomicBool::new(false);

    #[derive(zeroize::ZeroizeOnDrop)]
    struct MySecret([u8; 32]);

    impl zeroize::Zeroize for MySecret {
        fn zeroize(&mut self) {
            WIPED.store(true, Ordering::SeqCst);
            self.0.zeroize();
        }
    }

    {
        let _key = Fixed::new(MySecret([42u8; 32]));
        let _pw = Dynamic::new(MySecret([42u8; 32]));
    }

    assert!(WIPED.load(Ordering::SeqCst), "Zeroize was not called on drop");
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
```

### Updated `src/macros.rs`

```rust
// src/macros.rs
// Ergonomic constructor macro + type aliases only

/// Create a secret from an expression or literal.
#[macro_export]
macro_rules! secure {
    ($ty:ty, $expr:expr) => {
        $crate::Fixed::<$ty>::new($expr)
    };
    ($ty:ty, [$($val:expr),+ $(,)?]) => {
        $crate::Fixed::<$ty>::new([$($val),+])
    };
}

/// Define a fixed-size secret type alias.
#[macro_export]
macro_rules! fixed_alias {
    ($name:ident, $size:literal) => {
        pub type $name = $crate::Fixed<[u8; $size]>;
    };
}

/// Define a dynamic secret type alias.
#[macro_export]
macro_rules! dynamic_alias {
    ($name:ident, $ty:ty) => {
        pub type $name = $crate::Dynamic<$ty>;
    };
}
```

### Updated README.md (Full, with Detailed Dynamic Example)

# secure-gate

**Experimental crate — under active development**

Zero-cost, `no_std`-compatible secure wrappers for secrets — stack for fixed-size, heap for dynamic.

**Current status**: The crate is in an experimental phase. The public API is stabilizing, but breaking changes are still expected in future minor releases. Use in production with caution. Community testing and critique encouraged — open issues for feedback on security, performance, or ergonomics. Fuzz targets pending validation; no stability claims until full testing.

## v0.5.0 – 2025-11-22

Major overhaul from v0.4.3's learning-phase API. Clean break for simplicity and correctness.

### Breaking Changes
- Replaced `SecureGate<T>` with two honest types: `Fixed<T>` (stack/fixed-size) and `Dynamic<T>` (heap/dynamic).
- Removed `ZeroizeMode` and manual wiping — `zeroize` ≥1.8 handles spare capacity by default.
- Removed password specializations (`SecurePassword`, `SecurePasswordBuilder`) — use `Dynamic<String>`.
- Removed `unsafe-wipe` — safe by default.
- Migration guide below.

### Added
- True zero-cost for fixed-size secrets when `zeroize` off (no heap allocation).
- `Deref` / `DerefMut` ergonomics — secrets borrow like normal types.
- `secure!`, `fixed_alias!`, and `dynamic_alias!` macros for constructors and aliases.
- `into_inner()` for extraction.
- `finish_mut()` with `shrink_to_fit` for `Dynamic<String>` / `Vec<u8>`.
- `Clone` for `Dynamic<T>`.

### Fixed
- No `unsafe` when `zeroize` off (`forbid(unsafe_code)`).
- Full spare-capacity wipe via `zeroize`.
- Consistent API across modes.

### Improved
- Modular structure (`fixed.rs`, `dynamic.rs`, `macros.rs`, `zeroize.rs`, `serde.rs`).
- 9 unit tests covering zero-cost, wiping, ergonomics, serde, macros.

Fuzz testing in progress — stability claims pending full validation.

## Features

| Feature  | Effect |
|----------|--------|
| `zeroize` | Enables wiping + auto-drop zeroing (on by default) |
| `serde`  | Serialization support |

- `no_std` + `alloc` compatible.
- Redacted `Debug`.
- Test coverage includes zero-cost, forwarding, and drop behavior.

**Internal Usage of Dependencies**:
- `Fixed<T>` uses `zeroize::Zeroizing<T>` for stack-allocated, auto-zeroing fixed-size secrets.
- `Dynamic<T>` uses `secrecy::SecretBox<T>` for heap-allocated, leak-protected dynamic secrets.
- Both forward `ZeroizeOnDrop` and `Zeroize` for seamless integration.

## Installation

```toml
[dependencies]
secure-gate = "0.5.0"
```

With serde:
```toml
secure-gate = { version = "0.5.0", features = ["serde"] }
```

## Quick Start

```rust
use secure_gate::{Fixed, Dynamic, secure, fixed_alias, dynamic_alias};

// Fixed-size key (stack when zeroize off)
fixed_alias!(Aes256Key, 32);
let key: Aes256Key = [0u8; 32].into();

assert_eq!(key.len(), 32);
key[0] = 1;  // DerefMut

// Dynamic password (heap, full protection)
let mut pw = Dynamic::<String>::new("hunter2".to_string());

assert_eq!(pw.len(), 7);
assert_eq!(&*pw, "hunter2");  // Deref

pw.push('!');
pw.finish_mut();  // shrink_to_fit

// Macros
let iv = secure!([u8; 16], [1u8; 16]);
assert_eq!(iv.0, [1u8; 16]);

// Extraction
let extracted = key.into_inner();
assert_eq!(extracted, [1u8; 32]);
```

## Example Aliases

Use `fixed_alias!` for fixed-size types and `dynamic_alias!` for dynamic types. These generate self-documenting aliases.

### Fixed-Size (Stack-Optimized)

```rust
use secure_gate::fixed_alias;

// Crypto keys
fixed_alias!(Aes256Key, 32);
fixed_alias!(HmacSha256Key, 32);
fixed_alias!(X25519SecretKey, 32);

// Nonces and IVs
fixed_alias!(AesGcmIv12, 12);
fixed_alias!(AesCbcIv16, 16);
fixed_alias!(ChaCha20Nonce12, 12);
fixed_alias!(XChaCha20Nonce24, 24);

// Salts
fixed_alias!(Salt16, 16);

// Usage
let key: Aes256Key = [0u8; 32].into();
let iv = AesGcmIv12::new(rand::random::<[u8; 12]>());
```

### Dynamic-Size (Heap-Optimized)

```rust
use secure_gate::dynamic_alias;

// Strings and passwords
dynamic_alias!(Password, String);
dynamic_alias!(JwtSecret, String);

// Byte vectors
dynamic_alias!(Token, Vec<u8>);
dynamic_alias!(Payload, Vec<u8>);

// Usage
let pw: Password = Dynamic::new("hunter2".to_string());
let token: Token = Dynamic::new_boxed(Box::new(vec![0u8; 32]));

assert_eq!(pw.len(), 7);
pw.push('!');  // DerefMut
assert_eq!(&*pw, "hunter2!");
```

## Migration from v0.4.3

v0.5.0 is a clean break from v0.4.3's experimental API.

- `SecureGate<T>` → `Fixed<T>` (fixed-size) or `Dynamic<T>` (dynamic).
- `ZeroizeMode` / `new_full_wipe` → Removed; `zeroize` handles wiping.
- `SecurePassword` → `Dynamic<String>`.
- `expose_secret()` → `Deref` (e.g., `&*secret`).
- `unsafe-wipe` → Removed; safe by default.

Example migration:
```rust
// v0.4.3
let pw: SecurePassword = "hunter2".into();
pw.expose_secret_mut().push('!');

// v0.5.0
let mut pw = Dynamic::<String>::new("hunter2".to_string());
pw.push('!');
```

All v0.4.3 code breaks — this is intentional for the clean redesign.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full history.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.