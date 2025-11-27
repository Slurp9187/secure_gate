# secure-gate

Zero-cost, `no_std`-compatible wrappers for handling sensitive data in memory.

- `Fixed<T>` – stack-allocated, zero-cost wrapper.
- `Dynamic<T>` – heap-allocated wrapper with full `.into()` ergonomics.
- When the `zeroize` feature is enabled, `FixedZeroizing<T>` and `DynamicZeroizing<T>` provide automatic zeroing on drop.

## Installation

```toml
[dependencies]
secure-gate = "0.5.7"
```

With automatic zeroing (recommended):

```toml
secure-gate = { version = "0.5.7", features = ["zeroize"] }
```

With secure random generation (`OsRng`):

```toml
secure-gate = { version = "0.5.7", features = ["zeroize", "rand"] }
```

## Features

| Feature   | Description                                            |
|-----------|--------------------------------------------------------|
| `zeroize` | Enables `zeroize` integration (`Zeroizing`, `SecretBox`) |
| `rand`    | Enables `SecureRandomExt::random()` for `Fixed<[u8; N]>` types |
| `serde`   | Optional serialization support                         |
| `alloc`   | Required for `Dynamic<T>` (enabled by default)         |
| `std`     | Not required – works in `no_std` environments          |

## Quick Start

```rust
use secure_gate::{fixed_alias, dynamic_alias, SecureRandomExt};

fixed_alias!(Aes256Key, 32);
fixed_alias!(XChaCha20Nonce, 24);
dynamic_alias!(Password, String);
dynamic_alias!(JwtKey, Vec<u8>);

// Fixed-size secrets — perfect ergonomics
let key: Aes256Key = rng.gen().into();           // From<[u8; 32]>
let nonce: XChaCha20Nonce = rng.gen().into();

// With the `rand` feature — the dream becomes reality
let key = Aes256Key::random();        // cryptographically secure, zero-cost
let nonce = XChaCha20Nonce::random();

// Heap-based secrets — now just as beautiful!
let pw: Password = "hunter2".into();                    // From<&str>
let pw2: Password = "hunter2".to_string().into();       // From<String>
let jwt: JwtKey = secret_bytes.into();                  // From<Vec<u8>>

// Zeroizing heap secrets — same ergonomics
let temp_pw: DynamicZeroizing<String> = "temp123".into();
let temp_key: DynamicZeroizing<Vec<u8>> = vec![0u8; 32].into();

// Access is explicit and loud
let bytes: &[u8] = key.expose_secret();
let pw_str: &str = pw.expose_secret();
```

## Secure Random Generation (`rand` feature)

```rust
fixed_alias!(Aes128Key, 16);
fixed_alias!(Aes256Key, 32);
fixed_alias!(HmacKey, 64);

let key = Aes256Key::random();     // thread-local OsRng, <80ns after first use
let hmac_key = HmacKey::random();
```

- Powered by `rand::rngs::OsRng` via `TryRngCore::try_fill_bytes`
- Thread-local, lazily initialized, no heap allocation
- Panics on RNG failure (standard in high-assurance crypto)
- Works with all `fixed_alias!` types

## Memory Guarantees (`zeroize` feature enabled)

| Type                     | Allocation | Auto-zero on drop | Full capacity wiped | Slack memory eliminated | Notes |
|--------------------------|------------|-------------------|---------------------|--------------------------|-------|
| `Fixed<T>`               | Stack      | Yes (via `Zeroizing`) | Yes             | Yes (no heap)            | No allocation |
| `Dynamic<T>`             | Heap       | Yes (via `SecretBox`) | Yes             | No (until drop)          | Use `finish_mut()` to shrink |
| `FixedZeroizing<T>`      | Stack      | Yes                | Yes             | Yes                      | RAII wrapper |
| `DynamicZeroizing<T>`    | Heap       | Yes                | Yes             | No (until drop)          | `SecretBox` prevents copies |

**Important**: `DynamicZeroizing<T>` is accessed via `.expose_secret()` — it does **not** implement `Deref`.

## Macros

```rust
// Fixed-size secrets
secure!([u8; 32], rng.gen())                    // → Fixed<[u8; 32]>

// Heap secrets (non-zeroizing)
secure!(String, "pw".into())                    // → Dynamic<String>
secure!(Vec<u8>, data.to_vec())                 // → Dynamic<Vec<u8>>
secure!(heap Vec<u8>, payload)                  // → Dynamic<Vec<u8>>

// Zeroizing secrets (zeroize feature)
secure_zeroizing!([u8; 32], key)                // → FixedZeroizing<[u8; 32]>
secure_zeroizing!(heap String, "temp".into())   // → DynamicZeroizing<String>

// Type aliases — the recommended way
fixed_alias!(Aes256Key, 32)
dynamic_alias!(Password, String)
```

## Example Aliases

```rust
fixed_alias!(Aes128Key, 16);
fixed_alias!(Aes256Key, 32);
fixed_alias!(XChaCha20Nonce, 24);
dynamic_alias!(Password, String);
dynamic_alias!(JwtSigningKey, Vec<u8>);

// Usage — pure joy
let key = Aes256Key::random();           // with `rand` feature
let pw: Password = "hunter2".into();
let jwt: JwtSigningKey = secret_bytes.into();
```

### Zero-cost — proven on real hardware

| Implementation             | Median time | Max overhead vs raw |
|----------------------------|-------------|---------------------|
| raw `[u8; 32]`             | ~460 ps     | —                   |
| `Fixed<[u8; 32]>`          | ~460 ps     | **+28 ps**          |
| `fixed_alias!(Key, 32)`    | ~475 ps     | **+13 ps**          |

**Test machine** (2019-era laptop):  
Lenovo ThinkPad L13 • Intel Core i7-10510U • 16 GB RAM • Windows 10 Pro  
Measured with Criterion under real-world load.

Overhead is **< 0.1 CPU cycles** — indistinguishable from raw arrays.

[View full interactive report](https://slurp9187.github.io/secure-gate/benches/fixed_vs_raw/report/)

## Migration from v0.4.x

- `SecureGate<T>` → `Fixed<T>` (stack) or `Dynamic<T>` (heap)
- `.expose_secret()` → `value.expose_secret()`
- `.expose_secret_mut()` → `value.expose_secret_mut()`
- Automatic zeroing → `FixedZeroizing<T>` or `DynamicZeroizing<T>`

**Note**: `.view()` and `.view_mut()` are deprecated in v0.5.5 and will be removed in v0.6.0.

## Changelog

[See CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0