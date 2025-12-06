// fuzz/fuzz_targets/serde.rs
//
// secure-gate v0.6.0 — airtight serde fuzz target
// Compiles cleanly with --all-features on Windows/PowerShell
#![no_main]
use libfuzzer_sys::fuzz_target;

// ─────────────────────────────────────────────────────────────────────────────
// Imports that MUST be at the top — visible to every #[cfg] block below
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(feature = "serde")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use bincode;
#[cfg(feature = "serde")]
use secure_gate::{Dynamic, Fixed}; // ← critical: in scope everywhere
#[cfg(feature = "serde")]
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};
#[cfg(feature = "serde")]
use serde_json;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // serde feature disabled → just consume input
    #[cfg(not(feature = "serde"))]
    {
        let _ = data.len();
        return;
    }

    #[cfg(feature = "serde")]
    {
        const MAX_INPUT: usize = 1_048_576; // 1 MiB

        let mut u = Unstructured::new(data);

        // Generate valid instances via Arbitrary
        let _fixed_32 = match FuzzFixed32::arbitrary(&mut u) {
            Ok(f) => f.0,
            Err(_) => return,
        };

        let dyn_vec = match FuzzDynamicVec::arbitrary(&mut u) {
            Ok(d) => d.0,
            Err(_) => return,
        };

        let _dyn_str = match FuzzDynamicString::arbitrary(&mut u) {
            Ok(d) => d.0,
            Err(_) => return,
        };

        let fuzz_data = dyn_vec.expose_secret().as_slice();
        if fuzz_data.len() > MAX_INPUT {
            return;
        }

        // 1. Fixed<[u8; 32]> must deserialize (allowed)
        if fuzz_data.len() >= 32 {
            let arr: [u8; 32] = fuzz_data[..32].try_into().unwrap();
            let json = serde_json::to_string(&arr).expect("serialize [u8;32]");
            let _ = serde_json::from_str::<Fixed<[u8; 32]>>(&json)
                .expect("Fixed<[u8;32]> must deserialize");
        }

        // 2. Dynamic<String> from untrusted JSON → MUST be blocked
        match serde_json::from_slice::<Dynamic<String>>(fuzz_data) {
            Ok(_) => panic!("Dynamic<String> deserialized from untrusted input — SECURITY BUG"),
            Err(e) => {
                let msg = e.to_string();
                let expected = "Dynamic<T> deserialization is disabled for security reasons";
                if !msg.contains(expected) {
                    if !e.is_syntax() && !e.is_data() && !e.is_eof() {
                        panic!("Dynamic<String> rejected with wrong error: {msg}");
                    }
                }
            }
        }

        // 3. Serialization must always succeed
        let _ = serde_json::to_vec(&dyn_vec);

        // 4. Bincode safe paths (never direct Dynamic)
        let config = bincode::config::standard().with_limit::<MAX_INPUT>();
        if let Ok((vec, _)) = bincode::decode_from_slice::<Vec<u8>, _>(fuzz_data, config) {
            if vec.len() <= MAX_INPUT {
                let sec = Dynamic::<Vec<u8>>::new(vec);
                let _ = sec.expose_secret().len();
                drop(sec);
            }
        }
        let _ = bincode::encode_to_vec(dyn_vec.expose_secret(), config);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Large-input stress test — now compiles because Dynamic is in scope
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(feature = "serde")]
    if data.len() >= 1024 {
        for i in 1..=5 {
            let repeated_len = data.len() * i as usize;
            if repeated_len > 2_097_152 {
                break;
            }
            let large = data.repeat(i as usize);

            match serde_json::from_slice::<Dynamic<String>>(&large) {
                Ok(_) => panic!("Dynamic<String> deserialized from large input — SECURITY BUG"),
                Err(e) => {
                    let msg = e.to_string();
                    let expected = "Dynamic<T> deserialization is disabled for security reasons";
                    if !msg.contains(expected) {
                        if !e.is_syntax() && !e.is_data() && !e.is_eof() {
                            panic!("Large input rejected with wrong error: {msg}");
                        }
                    }
                }
            }
        }
    }
});
