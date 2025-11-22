// fuzz/fuzz_targets/expose.rs
//
// Fuzz Dynamic<T> and Fixed<T> deref/deref_mut usage across all public types
// (v0.5.0 – SecureGate, SecureBytes, SecureStr, SecurePassword, etc. are gone)
#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_gate::{Dynamic, Fixed};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Growable Vec<u8> — heavy mutation stress via DerefMut
    let mut vec_dyn = Dynamic::<Vec<u8>>::new(data.to_vec());
    vec_dyn.reverse();
    vec_dyn.truncate(data.len() % 64);
    vec_dyn.extend_from_slice(b"fuzz");
    vec_dyn.shrink_to_fit();

    // 2. Fixed-size array (stack-optimized, no heap)
    let mut key_arr = [0u8; 32];
    let copy_len = core::cmp::min(data.len(), 32);
    key_arr[..copy_len].copy_from_slice(&data[..copy_len]);
    let mut fixed_key = Fixed::new(key_arr);
    fixed_key[0] = 0xFF; // mutate via DerefMut

    // 3. String handling — owned String via Dynamic
    let owned = String::from_utf8_lossy(data).into_owned();
    let mut dyn_str = Dynamic::<String>::new(owned.clone());
    dyn_str.push('!'); // mutate via DerefMut

    // 4. Fixed-size nonce
    let mut nonce_arr = [0u8; 12];
    let copy_len = core::cmp::min(data.len(), 12);
    nonce_arr[..copy_len].copy_from_slice(&data[..copy_len]);
    let fixed_nonce = Fixed::new(nonce_arr);
    let _ = fixed_nonce.len(); // access via Deref

    // 5. Clone + Default + into_inner sanity
    let cloneable = Dynamic::<Vec<u8>>::new(vec![1u8, 2, 3]);
    let _ = cloneable.clone();
    let _default = Dynamic::<String>::new(String::new());

    // into_inner for extraction
    #[cfg(feature = "zeroize")]
    let _inner: Box<Vec<u8>> = cloneable.into_inner();

    // 6. finish_mut() helpers for Dynamic<String> / Vec<u8>
    {
        let mut v = Dynamic::<Vec<u8>>::new(vec![0u8; 1000]);
        v.truncate(10);
        let _ = v.finish_mut(); // shrink_to_fit + return &mut Vec<u8>
    }
    {
        let mut s = Dynamic::<String>::new("long string with excess capacity".to_string());
        s.push_str("!!!");
        let _ = s.finish_mut(); // shrink_to_fit + return &mut String
    }

    // 7. View helpers (Expose/ExposeMut) — optional zero-cost views
    {
        let view_imm = vec_dyn.view(); // Expose<'_, Vec<u8>>
        let _ = view_imm.len();

        let mut view_mut = fixed_key.view_mut(); // ExposeMut<'_, [u8; 32]>
        view_mut[1] = 0x42;
    }
});
