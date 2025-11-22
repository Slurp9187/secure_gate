# secure-gate

Zero-cost, `no_std`-compatible secure wrappers for secrets — stack for fixed-size, heap for dynamic.

## Status

**Current status**: The crate is in an experimental phase. The public API is stabilizing, but breaking changes are still expected in future minor releases. Use in production with caution. Community testing and critique encouraged — open issues for feedback on security, performance, or ergonomics. Fuzz targets implemented and passing on nightly CI (5 targets: `clone`, `expose`, `mut`, `parsing`, `serde`); no stability claims until full independent validation.

## Features

| Feature   | Effect                              |
|-----------|--------------------------------------|
| `zeroize` | Enables wiping + auto-drop zeroing (on by default) |
| `serde`   | Serialization support                |

- `no_std` + `alloc` compatible  
- Redacted `Debug`  
- Full unit test coverage  
- Continuous fuzz testing with libFuzzer (5 targets: `clone`, `expose`, `mut`, `parsing`, `serde`)  
- All fuzz targets currently passing on nightly CI (as of 2025-11-22)

**Memory Safety Guarantees (when `zeroize` enabled)**  
- `Fixed<T>` uses `zeroize::Zeroizing<T>` → stack-allocated, auto-zeroed on drop  
- `Dynamic<T>` uses `secrecy::SecretBox<T>` → heap-allocated, leak-resistant  
- `Vec<u8>` and `String` secrets are completely deallocated on drop or `zeroize()` (capacity drops to 0, buffer is freed) — stronger than spare-capacity wiping  

**Internal Usage of Dependencies**  
- `Fixed<T>` → `zeroize::Zeroizing<T>` (stack)  
- `Dynamic<T>` → `secrecy::SecretBox<T>` (heap)  
- Both implement `Zeroize` and `ZeroizeOnDrop` automatically when the `zeroize` feature is enabled

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
use secure_gate::{Fixed, Dynamic, secure, fixed_alias};

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
```

## Migration from v0.4.3

v0.5.0 is a clean break from the experimental v0.4.3 API.

| v0.4.3                         | v0.5.0 equivalent                                      |
|--------------------------------|---------------------------------------------------------|
| `SecureGate<T>`                | `Fixed<T>` (fixed-size) or `Dynamic<T>` (dynamic)      |
| `SecurePassword` / `SecurePasswordBuilder` | `Dynamic<String>`                                      |
| `expose_secret()` / `expose_secret_mut()` | direct `Deref` / `DerefMut` (`&*secret`, `&mut *secret`) |
| `ZeroizeMode`, `unsafe-wipe`   | removed — safe, full wiping is the default              |

Example:

```rust
// v0.4.3
let pw: SecurePassword = "hunter2".into();
pw.expose_secret_mut().push('!');

// v0.5.0
let mut pw = Dynamic::<String>::new("hunter2".to_string());
pw.push('!');   // DerefMut
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full history.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.