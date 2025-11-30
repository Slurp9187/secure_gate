# secure-gate

Zero-cost, `no_std`-compatible wrappers for handling sensitive data in memory.

- `Fixed<T>` – stack-allocated, zero-cost wrapper.
- `Dynamic<T>` – heap-allocated wrapper with full `.into()` ergonomics.
- When the `zeroize` feature is enabled, `FixedZeroizing<T>` and `DynamicZeroizing<T>` provide automatic zeroing on drop.

## Installation

```toml
[dependencies]
secure-gate = "0.5.8"
```

With automatic zeroing (recommended):

```toml
secure-gate = { version = "0.5.8", features = ["zeroize"] }
```

With secure random generation (`OsRng`):

```toml
secure-gate = { version = "0.5.8", features = ["zeroize", "rand"] }
```

With full ergonomics (recommended for application code):

```toml
secure-gate = { version = "0.5.8", features = ["zeroize", "rand", "conversions"] }
```

## Features

| Feature       | Description                                                                                     |
|---------------|-------------------------------------------------------------------------------------------------|
| `zeroize`     | Enables automatic memory wiping on drop via `zeroize` and `secrecy`                             |
| `rand`        | Enables `SecureRandomExt::random()` — cryptographically secure key/nonce generation           |
| `conversions` | **Optional** — adds `.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, and `.ct_eq()` to all fixed-size secrets |
| `serde`       | Optional serialization support (deserialization disabled for `Dynamic<T>` for security)       |

Works in `no_std` + `alloc` environments. Only pay for what you use.

## Quick Start

```rust
use secure_gate::{fixed_alias, dynamic_alias};

fixed_alias!(Aes256Key, 32);
fixed_alias!(XChaCha20Nonce, 24);
dynamic_alias!(Password, String);

// The dream — with `rand` feature
#[cfg(feature = "rand")]
{
    use secure_gate::SecureRandomExt;
    let key = Aes256Key::random();        // cryptographically secure, zero-cost
    let nonce = XChaCha20Nonce::random();
}

// With `conversions` feature — pure joy
#[cfg(feature = "conversions")]
{
    use secure_gate::SecureConversionsExt;
    let hex = key.to_hex();                   // "a1b2c3d4..."
    let b64 = key.to_base64url();             // safe for JSON
    assert!(key.ct_eq(&key));                 // constant-time, secure
}

// Heap secrets — beautiful ergonomics
let pw: Password = "hunter2".into();
```

## Secure Random Generation (`rand` feature)

```rust
#[cfg(feature = "rand")]
{
    use secure_gate::{fixed_alias, SecureRandomExt};
    fixed_alias!(Aes256Key, 32);
    let key = Aes256Key::random();  // thread-local OsRng, <80ns after first use
}
```

## Secure Conversions (`conversions` feature)

```rust
#[cfg(feature = "conversions")]
{
    use secure_gate::{fixed_alias, SecureConversionsExt};
    fixed_alias!(FileKey, 32);
    let key = FileKey::random();  // requires `rand` too

    println!("Key (hex): {}", key.to_hex());
    println!("Key (Base64URL): {}", key.to_base64url());
    assert!(key.ct_eq(&key));  // constant-time equality — timing-attack resistant
}
```

- `.to_hex()` / `.to_hex_upper()` → perfect for logging/debugging
- `.to_base64url()` → ideal for JSON export, URLs, config files
- `.ct_eq()` → **required** for secure comparison of secrets

## Memory Guarantees (`zeroize` feature enabled)

| Type                     | Allocation | Auto-zero on drop | Full capacity wiped | Slack memory eliminated | Notes |
|--------------------------|------------|-------------------|---------------------|--------------------------|-------|
| `Fixed<T>`               | Stack      | Yes               | Yes                 | Yes (no heap)            | No allocation |
| `Dynamic<T>`             | Heap       | Yes               | Yes                 | No (until drop)          | Use `finish_mut()` to shrink |
| `FixedZeroizing<T>`      | Stack      | Yes               | Yes                 | Yes                      | RAII wrapper |
| `DynamicZeroizing<T>`    | Heap       | Yes               | Yes                 | No (until drop)          | `SecretBox` prevents copies |

**Important**: `DynamicZeroizing<T>` is accessed via `.expose_secret()` — it does **not** implement `Deref`.

## Macros

```rust
// Fixed-size secrets
secure!([u8; 32], rng.gen())                    // → Fixed<[u8; 32]>

// Heap secrets (non-zeroizing)
secure!(String, "pw".into())                    // → Dynamic<String>
secure!(heap Vec<u8>, payload)                  // → Dynamic<Vec<u8>>

// Zeroizing secrets (zeroize feature)
secure_zeroizing!([u8; 32], key)                // → FixedZeroizing<[u8; 32]>

// Type aliases — the recommended way
fixed_alias!(Aes256Key, 32)
dynamic_alias!(Password, String)
```

## Example Aliases

```rust
fixed_alias!(Aes256Key, 32);
fixed_alias!(XChaCha20Nonce, 24);
dynamic_alias!(Password, String);
dynamic_alias!(JwtSigningKey, Vec<u8>);

#[cfg(all(feature = "rand", feature = "conversions"))]
{
    use secure_gate::{SecureRandomExt, SecureConversionsExt};
    let key = Aes256Key::random();
    let hex = key.to_hex();          // with `conversions` feature
    let pw: Password = "hunter2".into();
}
```

### Zero-cost — proven on real hardware

| Implementation             | Median time | Max overhead vs raw |
|----------------------------|-------------|---------------------|
| raw `[u8; 32]`             | ~460 ps     | —                   |
| `Fixed<[u8; 32]>`          | ~460 ps     | **+28 ps**          |
| `fixed_alias!(Key, 32)`    | ~475 ps     | **+13 ps**          |

Overhead is **< 0.1 CPU cycles** — indistinguishable from raw arrays.

[View full interactive report](https://slurp9187.github.io/secure-gate/benches/fixed_vs_raw/report/)

## Migration from v0.4.x

- `SecureGate<T>` → `Fixed<T>` (stack) or `Dynamic<T>` (heap)
- `.expose_secret()` → `value.expose_secret()`
- Automatic zeroing → `FixedZeroizing<T>` or `DynamicZeroizing<T>`

**Note**: `.view()` and `.view_mut()` are deprecated in v0.5.5 and will be removed in v0.6.0.

## Changelog

[See CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0