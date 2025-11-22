// fuzz/fuzz_targets/parsing.rs
//
// Fuzz target for all parsing paths — Dynamic<String>, Dynamic<Vec<u8>>, and extreme allocation stress
// (v0.5.0 – SecureStr, SecureBytes, SecurePassword, etc. are gone; use Dynamic<T> + Fixed<T>)
#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate_0_5_0::Dynamic;

const MAX_LEN: usize = 1_000_000; // 1MB cap to avoid OOM

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LEN {
        return;
    }

    // 1. Dynamic<Vec<u8>> — raw arbitrary bytes (no UTF-8 required)
    let dyn_bytes = Dynamic::<Vec<u8>>::new(data.to_vec());
    let _ = dyn_bytes.len();

    // 2. UTF-8 path — only if valid
    if let Ok(s) = std::str::from_utf8(data) {
        // String parsing → Dynamic<String>
        let dyn_str = Dynamic::<String>::new(s.to_string());
        let _ = dyn_str.len();

        // Stress: clone + to_string
        let cloned = dyn_str.clone();
        let _ = cloned.as_str().to_string();
        drop(cloned);

        // Edge cases with emoji glory
        let _ = Dynamic::<String>::new("".to_string());
        let _ = Dynamic::<String>::new("hello world".to_string());
        let _ = Dynamic::<String>::new("grinning face rocket".to_string()); // emoji preserved!

        // Allocation stress on long valid strings
        if s.len() > 1_000 {
            let _ = Dynamic::<String>::new(s.to_string());
        }
        if s.len() > 5_000 {
            let _ = Dynamic::<String>::new(s.to_string());
        }
    }

    // 3. Mutation stress — lossy UTF-8 → owned String → Dynamic<String>
    let owned = String::from_utf8_lossy(data).into_owned();
    let mut dyn_str = Dynamic::<String>::new(owned);
    dyn_str.push('!');
    dyn_str.push_str("_fuzz");
    dyn_str.clear();
    let _ = dyn_str.finish_mut(); // shrink_to_fit + return &mut String

    // 4. Extreme allocation stress — repeated data
    for i in 1..=10 {
        if data.len().saturating_mul(i as usize) > MAX_LEN {
            break;
        }
        let repeated = std::iter::repeat(data)
            .take(i.min(100))
            .flatten()
            .copied()
            .collect::<Vec<u8>>();
        let repeated_dyn: Dynamic<Vec<u8>> = Dynamic::new(repeated);
        let _ = repeated_dyn.len();
    }

    // Final drop — triggers zeroization when feature enabled
    drop(dyn_str);
});
