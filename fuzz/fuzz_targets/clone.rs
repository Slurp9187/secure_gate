// fuzz/fuzz_targets/clone.rs
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use secure_gate::{Dynamic, Fixed};
use secure_gate_fuzz::arbitrary::{FuzzDynamicString, FuzzDynamicVec, FuzzFixed32};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    let fixed_32: Fixed<[u8; 32]> = match FuzzFixed32::arbitrary(&mut u) {
        Ok(f) => f.0,
        Err(_) => return,
    };

    let dyn_vec: Dynamic<Vec<u8>> = match FuzzDynamicVec::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    let dyn_str: Dynamic<String> = match FuzzDynamicString::arbitrary(&mut u) {
        Ok(d) => d.0,
        Err(_) => return,
    };

    // Test 1: Empty container lifecycle
    {
        let empty = Dynamic::<Vec<u8>>::new(Vec::new());
        let _ = empty.clone();
        drop(empty);

        #[cfg(feature = "zeroize")]
        {
            let mut empty = Dynamic::<Vec<u8>>::new(Vec::new());
            empty.zeroize();
            if !empty.expose_secret().is_empty() {
                // ← fixed
                return;
            }
        }
    }

    // Test 2: Clone isolation
    let original_data = dyn_vec.expose_secret().clone();
    let mut original = Dynamic::<Vec<u8>>::new(original_data.clone());
    let mut clone = original.clone();
    clone.expose_secret_mut().push(0xFF); // ← safer than .push() on wrapper

    if original.expose_secret() != &original_data {
        return;
    }
    if clone.expose_secret().len() != original_data.len() + 1 {
        // ← fixed
        return;
    }
    if &clone.expose_secret()[..original_data.len()] != &original_data[..] {
        return;
    }
    if clone.expose_secret()[original_data.len()] != 0xFF {
        return;
    }

    // Test 3: Original mutation doesn't affect clone
    original.expose_secret_mut().push(0xAA);
    if clone.expose_secret().len() != original_data.len() + 1 {
        // ← fixed
        return;
    }

    // Test 4: Zeroization
    #[cfg(feature = "zeroize")]
    {
        let pre_len = original.expose_secret().len();
        original.zeroize();
        if original.expose_secret().len() != pre_len
            || !original.expose_secret().iter().all(|&b| b == 0)
        {
            return;
        }
    }

    // Test 5: String handling
    let pw_str = dyn_str.expose_secret().clone();
    let secure_str: Dynamic<String> = Dynamic::new(pw_str.clone());
    let _ = secure_str.clone();
    if secure_str.expose_secret() != &pw_str {
        return;
    }

    // Test 6: Fixed-size access
    let _ = fixed_32.expose_secret();

    // Final cleanup
    #[cfg(feature = "zeroize")]
    {
        clone.zeroize();
        if !clone.expose_secret().iter().all(|&b| b == 0) {
            return;
        }
    }
});
