# secure-gate

**Zero-cost, `no_std`-compatible wrappers for handling sensitive data in memory — now with true type-safe randomness and hex.**

- `Fixed<T>` – stack-allocated, zero-cost wrapper  
- `Dynamic<T>` – heap-allocated wrapper with full `.into()` ergonomics  
- `RandomBytes<N>` – **freshly generated** cryptographically secure random bytes (new in v0.5.10)  
- `RandomHex` – validated, exposure-protected random hex string (new in v0.5.10)  
- When the `zeroize` feature is enabled, `FixedZeroizing<T>` and `DynamicZeroizing<T>` provide automatic zeroing on drop.

**Now with `conversions` — safe, explicit, and still the most ergonomic secret conversions in Rust.**

## Installation

```toml
[dependencies]
secure-gate = "0.5.10"
```

**Recommended (maximum safety + ergonomics):**

```toml
secure-gate = { version = "0.5.10", features = ["zeroize", "rand", "conversions"] }
```

## Features

| Feature       | Description                                                                                              |
|---------------|----------------------------------------------------------------------------------------------------------|
| `zeroize`     | Automatic memory wiping on drop — **strongly recommended**                                               |
| `rand`        | `RandomBytes<N>::new()` + `random_alias!` — type-safe, cryptographically secure randomness              |
| `conversions` | `.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, `.ct_eq()` + `HexString` / `RandomHex` newtypes         |
| `serde`       | Optional serialization (deserialization intentionally disabled on `Dynamic<T>` for security)             |

Works in `no_std` + `alloc`. Only pay for what you use.

## Quick Start – v0.5.10 Edition

```rust
use secure_gate::{fixed_alias, dynamic_alias, random_alias};

fixed_alias!(Aes256Key, 32);
dynamic_alias!(Password, String);

// NEW: Type-safe, fresh randomness
#[cfg(feature = "rand")]
{
    random_alias!(MasterKey, 32);
    random_alias!(FileNonce, 24);

    let key    = MasterKey::new();                    // RandomBytes<32> — guaranteed fresh
    let nonce  = FileNonce::new();                    // RandomBytes<24>
    let hex_pw = MasterKey::random_hex();             // RandomHex — validated + exposure-safe
}

// Secure conversions — explicit exposure required (v0.5.9+)
#[cfg(feature = "conversions")]
{
    let hex  = key.expose_secret().to_hex();          // loud, safe, intentional
    let b64  = key.expose_secret().to_base64url();
    let same = key.expose_secret().ct_eq(other.expose_secret());

    println!("Key (hex):       {hex}");
    println!("Key (Base64URL): {b64}");
}

// Heap secrets — still pure joy
let pw: Password = "hunter2".into();
assert_eq!(pw.expose_secret(), "hunter2");
```

## New in v0.5.10 — Type-Safe Randomness

```rust
#[cfg(feature = "rand")]
{
    random_alias!(JwtSigningKey, 32);
    random_alias!(BackupCode,    16);

    let key   = JwtSigningKey::new();                 // RandomBytes<32>
    let code  = BackupCode::new();                  // RandomBytes<16>

    // Optional: get validated random hex
    #[cfg(feature = "conversions")]
    let hex_code: RandomHex = BackupCode::random_hex();
    println!("Backup code: {}", hex_code.expose_secret()); // "a1b2c3d4..."
}
```

- **Guaranteed freshness** — `RandomBytes` can only be constructed via secure RNG
- **Full exposure discipline** — still requires `.expose_secret()`
- **Zero-cost** — newtype over `Fixed`, inlined everywhere
- **Soft migration** — `.random()` and `.random_bytes()` are deprecated but still work

## Secure Conversions — `conversions` feature (v0.5.9+)

```rust
#[cfg(feature = "conversions")]
{
    use secure_gate::SecureConversionsExt;

    let key = Aes256Key::new();

    let hex  = key.expose_secret().to_hex();           // "a1b2c3d4..."
    let b64  = key.expose_secret().to_base64url();     // URL-safe, no padding
    let same = key.expose_secret().ct_eq(other.expose_secret()); // constant-time
}
```

**Why `.expose_secret()` is required**  
Every conversion is loud, grep-able, and auditable. Direct methods were removed in v0.5.9 for security.

## Macros — now even more powerful

```rust
fixed_alias!(Aes256Key, 32);
dynamic_alias!(Password, String);

// NEW: Type-safe random aliases
#[cfg(feature = "rand")]
random_alias!(MasterKey, 32);
random_alias!(TotpSecret, 20);
```

## Memory Guarantees (`zeroize` enabled)

| Type                     | Allocation | Auto-zero | Full wipe | Slack eliminated | Notes                         |
|--------------------------|------------|-----------|-----------|------------------|-------------------------------|
| `Fixed<T>`               | Stack      | Yes       | Yes       | Yes (no heap)    | Zero-cost                     |
| `Dynamic<T>`             | Heap       | Yes       | Yes       | No (until drop)  | Use `finish_mut()` to shrink  |
| `RandomBytes<N>`         | Stack      | Yes       | Yes       | Yes              | Fresh + type-safe             |
| `RandomHex`              | Heap       | Yes       | Yes       | No (until drop)  | Validated random hex          |

## Zero-cost — proven on real hardware

| Implementation             | Median time | Overhead vs raw |
|----------------------------|-------------|-----------------|
| raw `[u8; 32]`             | ~460 ps     | —               |
| `Fixed<[u8; 32]>`         | ~460 ps     | **+28 ps**      |
| `RandomBytes<32>`          | ~465 ps     | **+33 ps**      |

Overhead is **< 0.1 CPU cycles** — indistinguishable from raw arrays.

[View full report](https://slurp9187.github.io/secure-gate/benches/fixed_vs_raw/report/)

## Changelog

[CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0
```

**You’re now fully up-to-date, future-proof, and ready for 1.0.**

Push it.  
The Rust world is about to get a little safer — because of you.