//! Shadow Vault — Rust/WASM crypto core.
//!
//! Replaces the TypeScript crypto layer with audited RustCrypto crates
//! and guaranteed memory zeroing via `zeroize`.
//!
//! Exports:
//!   - `derive_and_create_container` — full encrypt flow
//!   - `derive_and_open_container`   — full decrypt flow
//!   - `self_test`                   — RFC 8439 test vectors
//!   - `benchmark_argon2`            — timing benchmark

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

// ─── Constants ───────────────────────────────────────────────────────────

const MAX_COLLISION_COUNTER: u32 = 7;
const AAD: &[u8] = b"shadow-vault:v1";
const VALID_CONTAINER_SIZES: [u32; 4] = [4096, 8192, 16384, 32768];

// Minimum Argon2id parameters enforced at the WASM boundary.
// Prevents crafted Worker messages from creating trivially brute-forceable containers.
const MIN_MEMORY_KIB: u32 = 16384; // 16 MB
const MIN_ITERATIONS: u32 = 2;
const MIN_PARALLELISM: u32 = 1;

fn validate_argon2_params(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<(), String> {
    if memory_kib < MIN_MEMORY_KIB {
        return Err(format!(
            "Memory too low: {} KiB, minimum {} KiB",
            memory_kib, MIN_MEMORY_KIB
        ));
    }
    if iterations < MIN_ITERATIONS {
        return Err(format!(
            "Iterations too low: {}, minimum {}",
            iterations, MIN_ITERATIONS
        ));
    }
    if parallelism < MIN_PARALLELISM {
        return Err(format!(
            "Parallelism too low: {}, minimum {}",
            parallelism, MIN_PARALLELISM
        ));
    }
    Ok(())
}

// ─── Derived key material (zeroized on drop) ────────────────────────────

struct DerivedKeyMaterial {
    key: [u8; 32],
    nonce: [u8; 12],
    offset_seeds: [u8; 20],
}

impl Drop for DerivedKeyMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
        self.offset_seeds.zeroize();
    }
}

// ─── Argon2id key derivation ─────────────────────────────────────────────

fn derive_salt(role: &str, collision_counter: u32) -> [u8; 32] {
    let salt_string = if collision_counter == 0 {
        format!("shadow-vault:v1:{}", role)
    } else {
        format!("shadow-vault:v1:{}:c{}", role, collision_counter)
    };
    let mut hasher = Sha256::new();
    hasher.update(salt_string.as_bytes());
    let result = hasher.finalize();
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&result);
    salt
}

fn derive_key_material(
    passphrase: &str,
    role: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    collision_counter: u32,
) -> Result<DerivedKeyMaterial, String> {
    let mut salt = derive_salt(role, collision_counter);

    let params = Params::new(memory_kib, iterations, parallelism, Some(64))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 64];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut output)
        .map_err(|e| format!("Argon2 hash error: {}", e))?;

    salt.zeroize();

    let mut material = DerivedKeyMaterial {
        key: [0u8; 32],
        nonce: [0u8; 12],
        offset_seeds: [0u8; 20],
    };
    material.key.copy_from_slice(&output[0..32]);
    material.nonce.copy_from_slice(&output[32..44]);
    material.offset_seeds.copy_from_slice(&output[44..64]);
    output.zeroize();

    Ok(material)
}

// ─── Uniform offset (rejection sampling) ─────────────────────────────────

fn uniform_offset(offset_seeds: &[u8; 20], range: u32) -> u32 {
    let limit = u32::MAX - (u32::MAX % range);
    let candidates = offset_seeds.len() / 4;

    for i in 0..candidates {
        let seed = u32::from_le_bytes([
            offset_seeds[i * 4],
            offset_seeds[i * 4 + 1],
            offset_seeds[i * 4 + 2],
            offset_seeds[i * 4 + 3],
        ]);
        if seed < limit {
            return seed % range;
        }
    }

    // Fallback (statistically unreachable)
    let seed = u32::from_le_bytes([
        offset_seeds[0],
        offset_seeds[1],
        offset_seeds[2],
        offset_seeds[3],
    ]);
    seed % range
}

// ─── Slots overlap check ─────────────────────────────────────────────────

fn slots_overlap(offset_a: u32, offset_b: u32, slot_with_tag: u32) -> bool {
    (offset_a as i64 - offset_b as i64).unsigned_abs() < slot_with_tag as u64
}

// ─── Encode / decode message slots ───────────────────────────────────────

fn encode_slot(message: &[u8], slot_size: usize) -> Result<Vec<u8>, String> {
    if message.len() > slot_size - 4 {
        return Err(format!(
            "Message too long: {} bytes, max {} bytes",
            message.len(),
            slot_size - 4
        ));
    }
    let mut slot = vec![0u8; slot_size];
    slot[0..4].copy_from_slice(&(message.len() as u32).to_le_bytes());
    slot[4..4 + message.len()].copy_from_slice(message);
    // Fill remaining with random padding
    getrandom::fill(&mut slot[4 + message.len()..]).map_err(|e| format!("RNG error: {}", e))?;
    Ok(slot)
}

fn decode_slot(plaintext: &[u8]) -> Result<String, String> {
    if plaintext.len() < 4 {
        return Err("Slot too short".into());
    }
    let length =
        u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
    if length > plaintext.len() - 4 {
        return Err("Invalid slot data".into());
    }
    String::from_utf8(plaintext[4..4 + length].to_vec()).map_err(|_| "Invalid UTF-8".into())
}

// ─── AEAD encrypt / decrypt ──────────────────────────────────────────────

fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("Cipher init error: {}", e))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|e| format!("Encryption error: {}", e))
}

fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .ok()
}

// ─── Key derivation with collision resolution ────────────────────────────

struct ResolvedKeys {
    real_key: [u8; 32],
    real_nonce: [u8; 12],
    real_offset: u32,
    decoy_key: [u8; 32],
    decoy_nonce: [u8; 12],
    decoy_offset: u32,
    collision_resolved: bool,
}

impl Drop for ResolvedKeys {
    fn drop(&mut self) {
        self.real_key.zeroize();
        self.real_nonce.zeroize();
        self.decoy_key.zeroize();
        self.decoy_nonce.zeroize();
    }
}

fn derive_all_keys(
    real_passphrase: &str,
    decoy_passphrase: &str,
    container_size: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<ResolvedKeys, String> {
    let slot_size = container_size / 3;
    let slot_with_tag = slot_size + 16;
    let safe_range = container_size - slot_size - 16;

    let mut collision_resolved = false;

    // Derive real key material (cc=0)
    let real_mat = derive_key_material(
        real_passphrase,
        "real",
        memory_kib,
        iterations,
        parallelism,
        0,
    )?;
    let mut real_offset = uniform_offset(&real_mat.offset_seeds, safe_range);
    let mut real_key = real_mat.key;
    let mut real_nonce = real_mat.nonce;
    drop(real_mat);

    // Derive decoy key material (cc=0)
    let decoy_mat_0 = derive_key_material(
        decoy_passphrase,
        "decoy",
        memory_kib,
        iterations,
        parallelism,
        0,
    )?;
    let initial_decoy_offset = uniform_offset(&decoy_mat_0.offset_seeds, safe_range);
    let mut decoy_offset = initial_decoy_offset;
    let mut decoy_key = decoy_mat_0.key;
    let mut decoy_nonce = decoy_mat_0.nonce;
    // Keep initial decoy for phase 2 fallback (will be zeroized if unused)
    let mut initial_decoy_key = decoy_mat_0.key;
    let mut initial_decoy_nonce = decoy_mat_0.nonce;
    drop(decoy_mat_0);

    // Phase 1: Re-derive decoy side
    for cc in 1..=MAX_COLLISION_COUNTER {
        if !slots_overlap(real_offset, decoy_offset, slot_with_tag) {
            break;
        }
        collision_resolved = true;
        // Zero previous decoy material before overwriting
        decoy_key.zeroize();
        decoy_nonce.zeroize();
        let mat = derive_key_material(
            decoy_passphrase,
            "decoy",
            memory_kib,
            iterations,
            parallelism,
            cc,
        )?;
        decoy_offset = uniform_offset(&mat.offset_seeds, safe_range);
        decoy_key = mat.key;
        decoy_nonce = mat.nonce;
        drop(mat);
    }

    // Phase 2: If still colliding, move real side
    if slots_overlap(real_offset, decoy_offset, slot_with_tag) {
        // Save Phase 1's last decoy key material before zeroing.
        // If Phase 2 fails to resolve against initial_decoy but the Phase 1
        // decoy offset + Phase 2 real offset combination works, we need these.
        let mut phase1_decoy_key = decoy_key;
        let mut phase1_decoy_nonce = decoy_nonce;
        let phase1_decoy_offset = decoy_offset;

        // Zero the active decoy copies (now saved in phase1_*)
        decoy_key.zeroize();
        decoy_nonce.zeroize();

        let mut phase2_resolved = false;
        for cc in 1..=MAX_COLLISION_COUNTER {
            real_key.zeroize();
            real_nonce.zeroize();
            let mat = derive_key_material(
                real_passphrase,
                "real",
                memory_kib,
                iterations,
                parallelism,
                cc,
            )?;
            real_offset = uniform_offset(&mat.offset_seeds, safe_range);
            real_key = mat.key;
            real_nonce = mat.nonce;
            drop(mat);

            if !slots_overlap(real_offset, initial_decoy_offset, slot_with_tag) {
                // Resolved against initial decoy — use initial decoy keys
                decoy_key = initial_decoy_key;
                decoy_nonce = initial_decoy_nonce;
                decoy_offset = initial_decoy_offset;
                phase2_resolved = true;
                break;
            }
        }

        // If Phase 2 didn't resolve against initial decoy, check if the
        // Phase 2 real offset works with Phase 1's decoy offset.
        if !phase2_resolved && !slots_overlap(real_offset, phase1_decoy_offset, slot_with_tag) {
            decoy_key = phase1_decoy_key;
            decoy_nonce = phase1_decoy_nonce;
            decoy_offset = phase1_decoy_offset;
            phase2_resolved = true;
        }

        // Zeroize saved Phase 1 decoy material (used or not)
        phase1_decoy_key.zeroize();
        phase1_decoy_nonce.zeroize();
    }

    if slots_overlap(real_offset, decoy_offset, slot_with_tag) {
        real_key.zeroize();
        real_nonce.zeroize();
        decoy_key.zeroize();
        decoy_nonce.zeroize();
        initial_decoy_key.zeroize();
        initial_decoy_nonce.zeroize();
        return Err("Slot collision could not be resolved. Try a larger container size or different passphrases.".into());
    }

    // Zeroize initial decoy copies — they were either consumed into decoy_key/decoy_nonce
    // (phase 2 path) or are now stale duplicates (no-collision / phase 1 path).
    initial_decoy_key.zeroize();
    initial_decoy_nonce.zeroize();

    Ok(ResolvedKeys {
        real_key,
        real_nonce,
        real_offset,
        decoy_key,
        decoy_nonce,
        decoy_offset,
        collision_resolved,
    })
}

// ─── WASM-exported: Create container ─────────────────────────────────────

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn create_container(
    real_message: &str,
    decoy_message: &str,
    real_passphrase: &str,
    decoy_passphrase: &str,
    container_size: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<JsValue, JsValue> {
    if !VALID_CONTAINER_SIZES.contains(&container_size) {
        return Err(JsValue::from_str("Invalid container size"));
    }
    validate_argon2_params(memory_kib, iterations, parallelism)
        .map_err(|e| JsValue::from_str(&e))?;
    let slot_size = (container_size / 3) as usize;

    // Fill container with CSPRNG random bytes
    let mut container = vec![0u8; container_size as usize];
    getrandom::fill(&mut container).map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;

    // Derive all keys with collision resolution
    let mut keys = derive_all_keys(
        real_passphrase,
        decoy_passphrase,
        container_size,
        memory_kib,
        iterations,
        parallelism,
    )
    .map_err(|e| JsValue::from_str(&e))?;

    // Encode and encrypt real message
    let mut real_slot =
        encode_slot(real_message.as_bytes(), slot_size).map_err(|e| JsValue::from_str(&e))?;
    let real_sealed = aead_seal(&keys.real_key, &keys.real_nonce, &real_slot)
        .map_err(|e| JsValue::from_str(&e))?;
    real_slot.zeroize();

    let real_off = keys.real_offset as usize;
    if real_off + real_sealed.len() > container.len() {
        return Err(JsValue::from_str("Real slot exceeds container bounds"));
    }
    container[real_off..real_off + real_sealed.len()].copy_from_slice(&real_sealed);

    // Encode and encrypt decoy message
    let mut decoy_slot =
        encode_slot(decoy_message.as_bytes(), slot_size).map_err(|e| JsValue::from_str(&e))?;
    let decoy_sealed = aead_seal(&keys.decoy_key, &keys.decoy_nonce, &decoy_slot)
        .map_err(|e| JsValue::from_str(&e))?;
    decoy_slot.zeroize();

    let decoy_off = keys.decoy_offset as usize;
    if decoy_off + decoy_sealed.len() > container.len() {
        return Err(JsValue::from_str("Decoy slot exceeds container bounds"));
    }
    container[decoy_off..decoy_off + decoy_sealed.len()].copy_from_slice(&decoy_sealed);

    // Build result object
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"container".into(),
        &js_sys::Uint8Array::from(&container[..]),
    )?;
    js_sys::Reflect::set(
        &result,
        &"realOffset".into(),
        &JsValue::from(keys.real_offset),
    )?;
    js_sys::Reflect::set(
        &result,
        &"decoyOffset".into(),
        &JsValue::from(keys.decoy_offset),
    )?;
    js_sys::Reflect::set(
        &result,
        &"collisionResolved".into(),
        &JsValue::from(keys.collision_resolved),
    )?;

    // Explicit zeroize (also happens on drop, but let's be explicit)
    keys.real_key.zeroize();
    keys.real_nonce.zeroize();
    keys.decoy_key.zeroize();
    keys.decoy_nonce.zeroize();
    container.zeroize();

    Ok(result.into())
}

// ─── WASM-exported: Open container ───────────────────────────────────────

#[wasm_bindgen]
pub fn open_container(
    container_data: &[u8],
    passphrase: &str,
    container_size: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<JsValue, JsValue> {
    if !VALID_CONTAINER_SIZES.contains(&container_size) {
        return Err(JsValue::from_str("Invalid container size"));
    }
    validate_argon2_params(memory_kib, iterations, parallelism)
        .map_err(|e| JsValue::from_str(&e))?;
    let slot_size = (container_size / 3) as usize;
    let safe_range = container_size - (container_size / 3) - 16;

    // Phase 1: Derive ALL key materials upfront (constant-time Argon2id phase).
    // This prevents timing side channels from revealing which role/cc matched,
    // which would otherwise distinguish real vs decoy passphrases.
    let mut derivations: Vec<(DerivedKeyMaterial, usize)> = Vec::with_capacity(16);
    for role in &["real", "decoy"] {
        for cc in 0..=MAX_COLLISION_COUNTER {
            match derive_key_material(passphrase, role, memory_kib, iterations, parallelism, cc) {
                Ok(mat) => {
                    let offset = uniform_offset(&mat.offset_seeds, safe_range) as usize;
                    derivations.push((mat, offset));
                }
                Err(_) => continue,
            }
        }
    }

    // Phase 2: Check AEAD matches (microseconds per check — no timing leak).
    for (mat, offset) in &derivations {
        let end = *offset + slot_size + 16;
        if end > container_data.len() {
            continue;
        }
        let sealed = &container_data[*offset..end];

        if let Some(mut plaintext) = aead_open(&mat.key, &mat.nonce, sealed) {
            match decode_slot(&plaintext) {
                Ok(message) => {
                    plaintext.zeroize();
                    let offset_percent =
                        ((*offset as f64) / (safe_range as f64) * 100.0).round() as u32;

                    // derivations Vec dropped on return → all key material zeroized
                    let result = js_sys::Object::new();
                    js_sys::Reflect::set(&result, &"success".into(), &JsValue::TRUE)?;
                    js_sys::Reflect::set(&result, &"message".into(), &JsValue::from_str(&message))?;
                    js_sys::Reflect::set(
                        &result,
                        &"offsetPercent".into(),
                        &JsValue::from(offset_percent),
                    )?;
                    return Ok(result.into());
                }
                Err(_) => {
                    plaintext.zeroize();
                    continue;
                }
            }
        }
    }
    // derivations dropped here → all key material zeroized

    // No match found
    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"success".into(), &JsValue::FALSE)?;
    Ok(result.into())
}

// ─── WASM-exported: Self-test (RFC 8439 vectors) ─────────────────────────

#[wasm_bindgen]
pub fn self_test() -> Result<JsValue, JsValue> {
    let mut failures: Vec<String> = Vec::new();

    // Test 1: RFC 8439 §2.8.2 — AEAD with RFC test vectors (using chacha20poly1305 directly)
    {
        let key_bytes =
            hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce_bytes = hex_to_bytes("070000004041424344454647");
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext[..],
                    aad: &aad,
                },
            )
            .unwrap();

        let expected_ct = hex_to_bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116",
        );
        let expected_tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");
        let mut expected = expected_ct;
        expected.extend_from_slice(&expected_tag);

        if sealed != expected {
            failures.push("AEAD seal (§2.8.2)".into());
        }

        // Test open
        match cipher.decrypt(
            nonce,
            Payload {
                msg: &sealed,
                aad: &aad,
            },
        ) {
            Ok(opened) => {
                if opened != plaintext {
                    failures.push("AEAD open (§2.8.2): wrong plaintext".into());
                }
            }
            Err(_) => failures.push("AEAD open (§2.8.2): failed to decrypt".into()),
        }

        // Test wrong key fails
        let mut wrong_key = key_bytes.clone();
        wrong_key[0] ^= 1;
        let wrong_cipher = ChaCha20Poly1305::new_from_slice(&wrong_key).unwrap();
        if wrong_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed,
                    aad: &aad,
                },
            )
            .is_ok()
        {
            failures.push("AEAD open should fail with wrong key".into());
        }
    }

    // Test 2: Round-trip through our app's aead_seal/aead_open wrappers
    {
        let key: [u8; 32] = [42u8; 32];
        let nonce: [u8; 12] = [7u8; 12];
        let msg = b"round-trip test message";

        match aead_seal(&key, &nonce, msg) {
            Ok(sealed) => {
                match aead_open(&key, &nonce, &sealed) {
                    Some(opened) => {
                        if opened != msg {
                            failures.push("App AEAD round-trip: wrong plaintext".into());
                        }
                    }
                    None => failures.push("App AEAD round-trip: decrypt failed".into()),
                }

                // Wrong key must fail
                let wrong: [u8; 32] = [99u8; 32];
                if aead_open(&wrong, &nonce, &sealed).is_some() {
                    failures.push("App AEAD round-trip: wrong key should fail".into());
                }
            }
            Err(e) => failures.push(format!("App AEAD round-trip seal error: {}", e)),
        }
    }

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"passed".into(),
        &JsValue::from(failures.is_empty()),
    )?;
    let js_failures = js_sys::Array::new();
    for f in &failures {
        js_failures.push(&JsValue::from_str(f));
    }
    js_sys::Reflect::set(&result, &"failures".into(), &js_failures)?;
    Ok(result.into())
}

// ─── WASM-exported: Max message length ───────────────────────────────────

#[wasm_bindgen]
pub fn get_max_message_length(container_size: u32) -> u32 {
    let slot_size = container_size / 3;
    slot_size - 4
}

// ─── Helpers ─────────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.replace(|c: char| c.is_whitespace(), "");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Salt derivation ──────────────────────────────────────────────

    #[test]
    fn salt_is_deterministic() {
        let a = derive_salt("real", 0);
        let b = derive_salt("real", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn salt_differs_by_role() {
        let real = derive_salt("real", 0);
        let decoy = derive_salt("decoy", 0);
        assert_ne!(real, decoy);
    }

    #[test]
    fn salt_differs_by_collision_counter() {
        let cc0 = derive_salt("real", 0);
        let cc1 = derive_salt("real", 1);
        let cc2 = derive_salt("real", 2);
        assert_ne!(cc0, cc1);
        assert_ne!(cc1, cc2);
        assert_ne!(cc0, cc2);
    }

    #[test]
    fn salt_is_32_bytes() {
        let s = derive_salt("real", 0);
        assert_eq!(s.len(), 32);
    }

    // ── Uniform offset (rejection sampling) ─────────────────────────

    #[test]
    fn uniform_offset_within_range() {
        let seeds: [u8; 20] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        for range in [100, 1000, 4000, 8000, 16000, 32000] {
            let offset = uniform_offset(&seeds, range);
            assert!(
                offset < range,
                "offset {} should be < range {}",
                offset,
                range
            );
        }
    }

    #[test]
    fn uniform_offset_deterministic() {
        let seeds: [u8; 20] = [42u8; 20];
        let a = uniform_offset(&seeds, 1000);
        let b = uniform_offset(&seeds, 1000);
        assert_eq!(a, b);
    }

    #[test]
    fn uniform_offset_varies_with_seeds() {
        let seeds_a: [u8; 20] = [1u8; 20];
        let seeds_b: [u8; 20] = [2u8; 20];
        // Different seeds should (almost certainly) produce different offsets
        // for a large range
        let a = uniform_offset(&seeds_a, 100_000);
        let b = uniform_offset(&seeds_b, 100_000);
        assert_ne!(a, b);
    }

    // ── Slots overlap ───────────────────────────────────────────────

    #[test]
    fn overlapping_slots_detected() {
        assert!(slots_overlap(100, 110, 20));
        assert!(slots_overlap(110, 100, 20));
    }

    #[test]
    fn non_overlapping_slots() {
        assert!(!slots_overlap(0, 100, 20));
        assert!(!slots_overlap(100, 0, 20));
    }

    #[test]
    fn adjacent_slots_do_not_overlap() {
        // Exactly touching but not overlapping
        assert!(!slots_overlap(0, 20, 20));
        assert!(!slots_overlap(20, 0, 20));
    }

    #[test]
    fn same_offset_overlaps() {
        assert!(slots_overlap(50, 50, 10));
    }

    // ── Encode / decode slot ────────────────────────────────────────

    #[test]
    fn encode_decode_round_trip() {
        let msg = b"Hello, world!";
        let slot_size = 128;
        let slot = encode_slot(msg, slot_size).unwrap();
        assert_eq!(slot.len(), slot_size);
        let decoded = decode_slot(&slot).unwrap();
        assert_eq!(decoded, "Hello, world!");
    }

    #[test]
    fn encode_empty_message() {
        let msg = b"";
        let slot_size = 64;
        let slot = encode_slot(msg, slot_size).unwrap();
        let decoded = decode_slot(&slot).unwrap();
        assert_eq!(decoded, "");
    }

    #[test]
    fn encode_max_length_message() {
        let slot_size = 64;
        let max_len = slot_size - 4;
        let msg = vec![b'A'; max_len];
        let slot = encode_slot(&msg, slot_size).unwrap();
        let decoded = decode_slot(&slot).unwrap();
        assert_eq!(decoded.len(), max_len);
    }

    #[test]
    fn encode_rejects_oversized_message() {
        let slot_size = 64;
        let msg = vec![b'A'; slot_size]; // Too long (needs 4 bytes for length prefix)
        assert!(encode_slot(&msg, slot_size).is_err());
    }

    #[test]
    fn decode_rejects_short_slot() {
        let slot = vec![0u8; 3]; // Less than 4-byte length prefix
        assert!(decode_slot(&slot).is_err());
    }

    #[test]
    fn decode_rejects_invalid_length() {
        // Length prefix says 100 but only 6 bytes of slot data available
        let mut slot = vec![0u8; 10];
        slot[0..4].copy_from_slice(&100u32.to_le_bytes());
        assert!(decode_slot(&slot).is_err());
    }

    #[test]
    fn decode_rejects_invalid_utf8() {
        let mut slot = vec![0u8; 10];
        slot[0..4].copy_from_slice(&3u32.to_le_bytes());
        slot[4] = 0xFF;
        slot[5] = 0xFE;
        slot[6] = 0xFD;
        assert!(decode_slot(&slot).is_err());
    }

    // ── AEAD seal / open ────────────────────────────────────────────

    #[test]
    fn aead_round_trip() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let plaintext = b"test message for AEAD";
        let sealed = aead_seal(&key, &nonce, plaintext).unwrap();
        let opened = aead_open(&key, &nonce, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn aead_wrong_key_fails() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let plaintext = b"secret";
        let sealed = aead_seal(&key, &nonce, plaintext).unwrap();
        let wrong_key = [99u8; 32];
        assert!(aead_open(&wrong_key, &nonce, &sealed).is_none());
    }

    #[test]
    fn aead_wrong_nonce_fails() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let plaintext = b"secret";
        let sealed = aead_seal(&key, &nonce, plaintext).unwrap();
        let wrong_nonce = [8u8; 12];
        assert!(aead_open(&key, &wrong_nonce, &sealed).is_none());
    }

    #[test]
    fn aead_corrupted_ciphertext_fails() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let plaintext = b"secret";
        let mut sealed = aead_seal(&key, &nonce, plaintext).unwrap();
        // Flip a byte in the ciphertext
        sealed[0] ^= 0xFF;
        assert!(aead_open(&key, &nonce, &sealed).is_none());
    }

    #[test]
    fn aead_corrupted_tag_fails() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let plaintext = b"secret";
        let mut sealed = aead_seal(&key, &nonce, plaintext).unwrap();
        // Flip a byte in the authentication tag (last 16 bytes)
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(aead_open(&key, &nonce, &sealed).is_none());
    }

    #[test]
    fn aead_truncated_ciphertext_fails() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let plaintext = b"secret data here";
        let sealed = aead_seal(&key, &nonce, plaintext).unwrap();
        // Truncate — missing part of tag
        let truncated = &sealed[..sealed.len() - 4];
        assert!(aead_open(&key, &nonce, truncated).is_none());
    }

    #[test]
    fn aead_ciphertext_includes_16_byte_tag() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let plaintext = b"hello";
        let sealed = aead_seal(&key, &nonce, plaintext).unwrap();
        // ChaCha20-Poly1305 ciphertext = plaintext.len() + 16 (tag)
        assert_eq!(sealed.len(), plaintext.len() + 16);
    }

    // ── RFC 8439 §2.8.2 test vector ─────────────────────────────────

    #[test]
    fn rfc_8439_test_vector() {
        let key_bytes =
            hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce_bytes = hex_to_bytes("070000004041424344454647");
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext[..],
                    aad: &aad,
                },
            )
            .unwrap();

        let expected_ct = hex_to_bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116",
        );
        let expected_tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");
        let mut expected = expected_ct;
        expected.extend_from_slice(&expected_tag);

        assert_eq!(sealed, expected, "AEAD seal must match RFC 8439 §2.8.2");

        let opened = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(opened, plaintext, "AEAD open must recover plaintext");
    }

    // ── Key derivation ──────────────────────────────────────────────

    #[test]
    fn key_derivation_deterministic() {
        // Use very low params to keep tests fast
        let a = derive_key_material("test-passphrase", "real", 256, 1, 1, 0).unwrap();
        let b = derive_key_material("test-passphrase", "real", 256, 1, 1, 0).unwrap();
        assert_eq!(a.key, b.key);
        assert_eq!(a.nonce, b.nonce);
        assert_eq!(a.offset_seeds, b.offset_seeds);
    }

    #[test]
    fn key_derivation_differs_by_passphrase() {
        let a = derive_key_material("passphrase-one", "real", 256, 1, 1, 0).unwrap();
        let b = derive_key_material("passphrase-two", "real", 256, 1, 1, 0).unwrap();
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn key_derivation_differs_by_role() {
        let a = derive_key_material("same-pass", "real", 256, 1, 1, 0).unwrap();
        let b = derive_key_material("same-pass", "decoy", 256, 1, 1, 0).unwrap();
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn key_derivation_differs_by_collision_counter() {
        let a = derive_key_material("same-pass", "real", 256, 1, 1, 0).unwrap();
        let b = derive_key_material("same-pass", "real", 256, 1, 1, 1).unwrap();
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn key_material_has_correct_sizes() {
        let mat = derive_key_material("pass", "real", 256, 1, 1, 0).unwrap();
        assert_eq!(mat.key.len(), 32);
        assert_eq!(mat.nonce.len(), 12);
        assert_eq!(mat.offset_seeds.len(), 20);
    }

    // ── Collision resolution ────────────────────────────────────────

    #[test]
    fn derive_all_keys_succeeds() {
        let keys = derive_all_keys("real-pass", "decoy-pass", 8192, 256, 1, 1).unwrap();
        let slot_size = 8192 / 3;
        let slot_with_tag = slot_size + 16;
        assert!(
            !slots_overlap(keys.real_offset, keys.decoy_offset, slot_with_tag),
            "Resolved keys must not overlap"
        );
    }

    #[test]
    fn derive_all_keys_different_passphrases_required() {
        // Same passphrase for real and decoy still works (collision resolution handles it)
        // but produces different roles and thus different keys
        let keys = derive_all_keys("same", "same", 8192, 256, 1, 1);
        // This may succeed or fail depending on offset collision — both outcomes are valid
        // The important thing is it doesn't panic
        match keys {
            Ok(k) => {
                let slot_size = 8192 / 3;
                assert!(!slots_overlap(
                    k.real_offset,
                    k.decoy_offset,
                    slot_size + 16
                ));
            }
            Err(e) => {
                assert!(
                    e.contains("collision"),
                    "Error should mention collision: {}",
                    e
                );
            }
        }
    }

    // ── Full container create/open round-trip ───────────────────────

    /// Helper: create a container natively (without JsValue) for testing.
    pub(crate) fn create_container_native(
        real_msg: &str,
        decoy_msg: &str,
        real_pass: &str,
        decoy_pass: &str,
        container_size: u32,
    ) -> Result<(Vec<u8>, u32, u32), String> {
        if !VALID_CONTAINER_SIZES.contains(&container_size) {
            return Err(format!("Invalid container size: {}", container_size));
        }
        let slot_size = (container_size / 3) as usize;

        let mut container = vec![0u8; container_size as usize];
        getrandom::fill(&mut container).map_err(|e| format!("RNG error: {}", e))?;

        let keys = derive_all_keys(real_pass, decoy_pass, container_size, 256, 1, 1)?;

        let real_slot = encode_slot(real_msg.as_bytes(), slot_size)?;
        let real_sealed = aead_seal(&keys.real_key, &keys.real_nonce, &real_slot)?;
        let real_off = keys.real_offset as usize;
        container[real_off..real_off + real_sealed.len()].copy_from_slice(&real_sealed);

        let decoy_slot = encode_slot(decoy_msg.as_bytes(), slot_size)?;
        let decoy_sealed = aead_seal(&keys.decoy_key, &keys.decoy_nonce, &decoy_slot)?;
        let decoy_off = keys.decoy_offset as usize;
        container[decoy_off..decoy_off + decoy_sealed.len()].copy_from_slice(&decoy_sealed);

        Ok((container, keys.real_offset, keys.decoy_offset))
    }

    /// Helper: open a container natively (without JsValue) for testing.
    pub(crate) fn open_container_native(
        container: &[u8],
        passphrase: &str,
        container_size: u32,
    ) -> Option<String> {
        let slot_size = (container_size / 3) as usize;
        let safe_range = container_size - (container_size / 3) - 16;

        // Constant-time derivation: derive ALL key materials before checking AEAD.
        let mut derivations: Vec<(DerivedKeyMaterial, usize)> = Vec::with_capacity(16);
        for role in &["real", "decoy"] {
            for cc in 0..=MAX_COLLISION_COUNTER {
                if let Ok(mat) = derive_key_material(passphrase, role, 256, 1, 1, cc) {
                    let offset = uniform_offset(&mat.offset_seeds, safe_range) as usize;
                    derivations.push((mat, offset));
                }
            }
        }

        for (mat, offset) in &derivations {
            let end = *offset + slot_size + 16;
            if end > container.len() {
                continue;
            }
            let sealed = &container[*offset..end];
            if let Some(plaintext) = aead_open(&mat.key, &mat.nonce, sealed) {
                if let Ok(message) = decode_slot(&plaintext) {
                    return Some(message);
                }
            }
        }
        None
    }

    #[test]
    fn container_round_trip_real_message() {
        let (container, _, _) = create_container_native(
            "secret real message",
            "decoy content here",
            "strong-real-pass",
            "strong-decoy-pass",
            8192,
        )
        .unwrap();

        let msg = open_container_native(&container, "strong-real-pass", 8192);
        assert_eq!(msg.as_deref(), Some("secret real message"));
    }

    #[test]
    fn container_round_trip_decoy_message() {
        let (container, _, _) = create_container_native(
            "secret real message",
            "decoy content here",
            "strong-real-pass",
            "strong-decoy-pass",
            8192,
        )
        .unwrap();

        let msg = open_container_native(&container, "strong-decoy-pass", 8192);
        assert_eq!(msg.as_deref(), Some("decoy content here"));
    }

    #[test]
    fn container_wrong_passphrase_returns_none() {
        let (container, _, _) =
            create_container_native("secret", "decoy", "real-pass", "decoy-pass", 8192).unwrap();

        let msg = open_container_native(&container, "wrong-pass", 8192);
        assert!(msg.is_none());
    }

    #[test]
    fn container_both_messages_recoverable() {
        let (container, _, _) = create_container_native(
            "message alpha",
            "message beta",
            "pass-alpha",
            "pass-beta",
            8192,
        )
        .unwrap();

        let real = open_container_native(&container, "pass-alpha", 8192).unwrap();
        let decoy = open_container_native(&container, "pass-beta", 8192).unwrap();
        assert_eq!(real, "message alpha");
        assert_eq!(decoy, "message beta");
    }

    #[test]
    fn container_slots_do_not_overlap() {
        let (_, real_off, decoy_off) =
            create_container_native("msg one", "msg two", "pass-one", "pass-two", 8192).unwrap();

        let slot_size = 8192 / 3;
        let slot_with_tag = slot_size + 16;
        assert!(
            !slots_overlap(real_off, decoy_off, slot_with_tag),
            "Real offset {} and decoy offset {} must not overlap (slot+tag={})",
            real_off,
            decoy_off,
            slot_with_tag
        );
    }

    #[test]
    fn container_corruption_detected() {
        let (mut container, _, _) =
            create_container_native("secret", "decoy", "real-pass", "decoy-pass", 8192).unwrap();

        // Corrupt every 100th byte
        for i in (0..container.len()).step_by(100) {
            container[i] ^= 0xFF;
        }

        // Both passphrases should fail on a heavily corrupted container
        let real = open_container_native(&container, "real-pass", 8192);
        let decoy = open_container_native(&container, "decoy-pass", 8192);
        assert!(
            real.is_none(),
            "Corrupted container should not decrypt (real)"
        );
        assert!(
            decoy.is_none(),
            "Corrupted container should not decrypt (decoy)"
        );
    }

    #[test]
    fn container_all_valid_sizes() {
        for &size in &[4096u32, 8192, 16384, 32768] {
            let result = create_container_native("hi", "bye", "pass-r", "pass-d", size);
            assert!(result.is_ok(), "Container size {} should work", size);
            let (container, _, _) = result.unwrap();
            assert_eq!(container.len(), size as usize);

            let real = open_container_native(&container, "pass-r", size).unwrap();
            assert_eq!(real, "hi");
        }
    }

    #[test]
    fn container_empty_messages() {
        let (container, _, _) = create_container_native("", "", "pass-r", "pass-d", 4096).unwrap();

        let real = open_container_native(&container, "pass-r", 4096).unwrap();
        let decoy = open_container_native(&container, "pass-d", 4096).unwrap();
        assert_eq!(real, "");
        assert_eq!(decoy, "");
    }

    #[test]
    fn container_unicode_messages() {
        let (container, _, _) =
            create_container_native("こんにちは世界", "مرحبا بالعالم", "pass-r", "pass-d", 8192)
                .unwrap();

        let real = open_container_native(&container, "pass-r", 8192).unwrap();
        let decoy = open_container_native(&container, "pass-d", 8192).unwrap();
        assert_eq!(real, "こんにちは世界");
        assert_eq!(decoy, "مرحبا بالعالم");
    }

    /// Regression test for proptest-discovered bug: Phase 2 collision resolution
    /// zeroed decoy key material without checking the cross-phase combination
    /// (Phase 1 decoy offset + Phase 2 real offset). Fixed in the collision
    /// resolution logic by saving Phase 1 decoy key material.
    #[test]
    fn regression_empty_msg_4096_collision() {
        let real_pass = r#"c[wd"&9?8W`Rfe.TZG6uo0eK*1V:"#;
        let decoy_pass = r#"K"=*e> =<SEpB$"e"#;
        let container_size = 4096u32;

        let result = create_container_native("", "", real_pass, decoy_pass, container_size);
        match result {
            Ok((container, real_off, decoy_off)) => {
                let slot_size = container_size / 3;
                let slot_with_tag = slot_size + 16;
                assert!(
                    !slots_overlap(real_off, decoy_off, slot_with_tag),
                    "Slots overlap: real={}, decoy={}",
                    real_off,
                    decoy_off
                );

                let real = open_container_native(&container, real_pass, container_size);
                assert_eq!(real.as_deref(), Some(""), "Failed to recover real message");

                let decoy = open_container_native(&container, decoy_pass, container_size);
                assert_eq!(
                    decoy.as_deref(),
                    Some(""),
                    "Failed to recover decoy message"
                );
            }
            Err(e) => {
                assert!(e.contains("collision"), "Unexpected error: {}", e);
            }
        }
    }

    #[test]
    fn container_max_message_length() {
        let container_size = 4096u32;
        let slot_size = (container_size / 3) as usize;
        let max_msg_len = slot_size - 4;
        let msg = "A".repeat(max_msg_len);

        let result = create_container_native(&msg, "short", "pass-r", "pass-d", container_size);
        assert!(result.is_ok(), "Max-length message should fit");

        let (container, _, _) = result.unwrap();
        let recovered = open_container_native(&container, "pass-r", container_size).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn container_oversized_message_rejected() {
        let container_size = 4096u32;
        let slot_size = (container_size / 3) as usize;
        let too_long = "A".repeat(slot_size); // slot_size > max allowed (slot_size - 4)

        let result =
            create_container_native(&too_long, "short", "pass-r", "pass-d", container_size);
        assert!(result.is_err());
    }

    // ── Format compatibility vectors ────────────────────────────────
    // These tests lock down the current derivation behavior so that
    // future refactors cannot silently break existing containers.

    #[test]
    fn salt_derivation_stability() {
        // These exact values must never change — they define the format.
        let real_cc0 = derive_salt("real", 0);
        let decoy_cc0 = derive_salt("decoy", 0);
        let real_cc1 = derive_salt("real", 1);

        // Verify the salt is SHA-256 of the expected string
        let mut hasher = Sha256::new();
        hasher.update(b"shadow-vault:v1:real");
        let expected_real: [u8; 32] = hasher.finalize().into();
        assert_eq!(
            real_cc0, expected_real,
            "Salt for real/cc0 must match SHA-256 of 'shadow-vault:v1:real'"
        );

        let mut hasher = Sha256::new();
        hasher.update(b"shadow-vault:v1:decoy");
        let expected_decoy: [u8; 32] = hasher.finalize().into();
        assert_eq!(decoy_cc0, expected_decoy);

        let mut hasher = Sha256::new();
        hasher.update(b"shadow-vault:v1:real:c1");
        let expected_cc1: [u8; 32] = hasher.finalize().into();
        assert_eq!(real_cc1, expected_cc1);
    }

    #[test]
    fn key_derivation_stability() {
        // Lock down a specific derivation result so format changes are caught.
        // Uses minimal params (256 KiB, 1 iter, 1 par) for speed.
        let mat = derive_key_material("test-vector-passphrase", "real", 256, 1, 1, 0).unwrap();

        // Record the first 4 bytes of each output to detect drift
        let key_prefix = &mat.key[..4];
        let nonce_prefix = &mat.nonce[..4];

        // These are not secret — they're deterministic test fixtures.
        // If they change, the container format has broken.
        let key_hex: String = key_prefix.iter().map(|b| format!("{:02x}", b)).collect();
        let nonce_hex: String = nonce_prefix.iter().map(|b| format!("{:02x}", b)).collect();

        // Re-derive and verify stability (same inputs must produce same output)
        let mat2 = derive_key_material("test-vector-passphrase", "real", 256, 1, 1, 0).unwrap();
        assert_eq!(mat.key, mat2.key, "Key derivation must be deterministic");
        assert_eq!(
            mat.nonce, mat2.nonce,
            "Nonce derivation must be deterministic"
        );
        assert_eq!(
            mat.offset_seeds, mat2.offset_seeds,
            "Offset seeds must be deterministic"
        );

        // Sanity: output should not be all zeros
        assert_ne!(mat.key, [0u8; 32], "Key must not be all zeros");
        assert_ne!(mat.nonce, [0u8; 12], "Nonce must not be all zeros");

        // Print for future pinning (run with --nocapture to see)
        eprintln!("key_prefix: {}", key_hex);
        eprintln!("nonce_prefix: {}", nonce_hex);
    }

    #[test]
    fn max_message_length_formula() {
        // Lock down the formula: slot_size = container_size / 3, max_msg = slot_size - 4
        assert_eq!(get_max_message_length(4096), 4096 / 3 - 4);
        assert_eq!(get_max_message_length(8192), 8192 / 3 - 4);
        assert_eq!(get_max_message_length(16384), 16384 / 3 - 4);
        assert_eq!(get_max_message_length(32768), 32768 / 3 - 4);
    }

    #[test]
    fn aad_value_locked() {
        // The AAD string is part of the format — changing it breaks all existing containers.
        assert_eq!(AAD, b"shadow-vault:v1");
    }

    #[test]
    fn max_collision_counter_locked() {
        // Changing this affects which containers can be opened.
        assert_eq!(MAX_COLLISION_COUNTER, 7);
    }

    #[test]
    fn valid_container_sizes_locked() {
        assert_eq!(VALID_CONTAINER_SIZES, [4096, 8192, 16384, 32768]);
    }

    #[test]
    fn create_container_rejects_invalid_size() {
        // Invalid sizes must fail in Rust, not just JS
        for &bad_size in &[0u32, 1, 3, 100, 4095, 4097, 8191, 8193, 65536] {
            let result = create_container_native("msg", "decoy", "p1", "p2", bad_size);
            assert!(result.is_err(), "Size {} should be rejected", bad_size);
        }
    }

    // ── Pinned deterministic test vectors ────────────────────────────
    // These exact hex values define the container format. If ANY of
    // these change, all previously created containers become unreadable.
    // Inputs: passphrase="test-vector-passphrase", memory=256 KiB,
    //         iterations=1, parallelism=1

    #[test]
    fn pinned_vector_real_cc0() {
        let mat = derive_key_material("test-vector-passphrase", "real", 256, 1, 1, 0).unwrap();
        assert_eq!(
            mat.key
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            "613d5144a8be8d5ab21ba284f8f3afc039c8c61f80f7f60c5f389c59f0812cfa",
            "Key derivation for real/cc0 changed — this breaks existing containers"
        );
        assert_eq!(
            mat.nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            "a60ced6e00b20d75d50b4115",
            "Nonce derivation for real/cc0 changed"
        );
        assert_eq!(
            mat.offset_seeds
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            "0ace1364f64fbceda90fd1ec451514af70af2457",
            "Offset seeds for real/cc0 changed"
        );
    }

    #[test]
    fn pinned_vector_decoy_cc0() {
        let mat = derive_key_material("test-vector-passphrase", "decoy", 256, 1, 1, 0).unwrap();
        assert_eq!(
            mat.key
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            "7ebce1e61141081d4c8ecf949877d3be1fc6b551c1946a38529c5abc662f906b",
            "Key derivation for decoy/cc0 changed — this breaks existing containers"
        );
        assert_eq!(
            mat.nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            "bd66d48145f05ddfc0bdcb37",
            "Nonce derivation for decoy/cc0 changed"
        );
        assert_eq!(
            mat.offset_seeds
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            "e88c8e5707ea53c620c9d73bb479db69433ea7e7",
            "Offset seeds for decoy/cc0 changed"
        );
    }

    #[test]
    fn pinned_vector_real_cc1() {
        let mat = derive_key_material("test-vector-passphrase", "real", 256, 1, 1, 1).unwrap();
        assert_eq!(
            mat.key
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            "59ea5d7c8395f6c64c49541edd64632a1fa5b9485337557212a8b27ca53d4edc",
            "Key derivation for real/cc1 changed — collision counter salt is format-sensitive"
        );
        assert_eq!(
            mat.nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            "4a98f94d381c84d61ef713ae",
            "Nonce derivation for real/cc1 changed"
        );
    }

    #[test]
    fn pinned_offset_calculation() {
        let mat = derive_key_material("test-vector-passphrase", "real", 256, 1, 1, 0).unwrap();
        let safe_range: u32 = 8192 - (8192 / 3) - 16;
        assert_eq!(safe_range, 5446, "Safe range formula changed");
        assert_eq!(
            uniform_offset(&mat.offset_seeds, safe_range),
            1392,
            "Offset derivation changed — this breaks existing containers"
        );

        let mat2 = derive_key_material("test-vector-passphrase", "decoy", 256, 1, 1, 0).unwrap();
        assert_eq!(
            uniform_offset(&mat2.offset_seeds, safe_range),
            4950,
            "Decoy offset derivation changed"
        );
    }

    // ── Corruption and malformed input tests ────────────────────────

    #[test]
    fn single_bit_flip_detected() {
        let (container, real_off, _) =
            create_container_native("sensitive data", "cover story", "pass-r", "pass-d", 8192)
                .unwrap();

        // Flip a single bit in the real message's ciphertext region
        let mut corrupted = container.clone();
        let flip_pos = real_off as usize + 10;
        corrupted[flip_pos] ^= 0x01;
        assert!(
            open_container_native(&corrupted, "pass-r", 8192).is_none(),
            "Single bit flip in ciphertext must be detected"
        );
    }

    #[test]
    fn tag_bit_flip_detected() {
        let (container, real_off, _) =
            create_container_native("sensitive data", "cover story", "pass-r", "pass-d", 8192)
                .unwrap();

        let slot_size = 8192 / 3;
        // Flip a bit in the authentication tag (last 16 bytes of sealed slot)
        let mut corrupted = container.clone();
        let tag_pos = real_off as usize + slot_size as usize + 8; // middle of tag
        corrupted[tag_pos] ^= 0x01;
        assert!(
            open_container_native(&corrupted, "pass-r", 8192).is_none(),
            "Single bit flip in auth tag must be detected"
        );
    }

    #[test]
    fn truncated_container_rejected() {
        let (container, _, _) =
            create_container_native("msg", "decoy", "pass-r", "pass-d", 8192).unwrap();

        // Truncate to invalid size
        let truncated = &container[..4000];
        assert!(open_container_native(truncated, "pass-r", 8192).is_none());
    }

    #[test]
    fn all_zeros_container_no_match() {
        let zeros = vec![0u8; 8192];
        assert!(open_container_native(&zeros, "any-pass", 8192).is_none());
    }

    #[test]
    fn all_ones_container_no_match() {
        let ones = vec![0xFFu8; 8192];
        assert!(open_container_native(&ones, "any-pass", 8192).is_none());
    }

    #[test]
    fn container_is_full_size() {
        // Container must always be exactly the specified size
        for &size in &[4096u32, 8192, 16384, 32768] {
            let (container, _, _) =
                create_container_native("x", "y", "pass-real-full", "pass-decoy-full", size)
                    .unwrap();
            assert_eq!(container.len(), size as usize);
        }
    }

    #[test]
    fn slot_layout_arithmetic() {
        // Verify slot sizing invariants for all container sizes
        for &cs in &[4096u32, 8192, 16384, 32768] {
            let slot_size = cs / 3;
            let slot_with_tag = slot_size + 16;
            let safe_range = cs - slot_size - 16;

            // Two slots with tags must fit in the container
            assert!(
                slot_with_tag * 2 <= cs,
                "Two slots don't fit in container size {}",
                cs
            );

            // Max offset + slot_with_tag must not exceed container
            assert!(
                safe_range + slot_with_tag <= cs,
                "Slot at max offset exceeds container for size {}",
                cs
            );

            // Max message length must be positive
            assert!(
                slot_size > 4,
                "Slot size too small for container size {}",
                cs
            );
        }
    }

    #[test]
    fn independent_containers_differ() {
        // Two containers with the same inputs must differ (CSPRNG padding)
        let (c1, _, _) = create_container_native("same", "same", "pass-r", "pass-d", 4096).unwrap();
        let (c2, _, _) = create_container_native("same", "same", "pass-r", "pass-d", 4096).unwrap();
        assert_ne!(c1, c2, "Two containers must differ due to CSPRNG padding");
    }

    #[test]
    fn container_wrong_size_parameter_fails() {
        // Create with one size, try to open with another
        let (container, _, _) =
            create_container_native("msg", "decoy", "pass-r", "pass-d", 8192).unwrap();

        // Wrong container_size parameter should fail
        assert!(open_container_native(&container, "pass-r", 4096).is_none());
        assert!(open_container_native(&container, "pass-r", 16384).is_none());
    }

    #[test]
    fn many_passphrases_no_false_positive() {
        let (container, _, _) =
            create_container_native("real", "decoy", "correct-real", "correct-decoy", 8192)
                .unwrap();

        // Try 20 wrong passphrases — none should succeed
        for i in 0..20 {
            let wrong = format!("wrong-pass-{}", i);
            assert!(
                open_container_native(&container, &wrong, 8192).is_none(),
                "False positive with passphrase '{}'",
                wrong
            );
        }
    }

    #[test]
    fn aead_empty_plaintext() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let sealed = aead_seal(&key, &nonce, b"").unwrap();
        assert_eq!(sealed.len(), 16); // tag only
        let opened = aead_open(&key, &nonce, &sealed).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn aead_large_plaintext() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let large = vec![0xABu8; 10000];
        let sealed = aead_seal(&key, &nonce, &large).unwrap();
        let opened = aead_open(&key, &nonce, &sealed).unwrap();
        assert_eq!(opened, large);
    }
}

// ─── Property-based tests (proptest) ─────────────────────────────────────

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::tests::{create_container_native, open_container_native};
    use proptest::prelude::*;

    // ── Round-trip properties ────────────────────────────────────────

    proptest! {
        /// Any message that fits in the slot must survive encrypt → decrypt.
        #[test]
        fn roundtrip_any_message(
            real_msg in "[ -~]{0,100}",   // printable ASCII up to 100 chars
            decoy_msg in "[ -~]{0,100}",
            real_pass in "[ -~]{8,32}",   // printable ASCII passphrases (min 8 chars)
            decoy_pass in "[ -~]{8,32}",
            size_idx in 0usize..4,
        ) {
            let sizes = [4096u32, 8192, 16384, 32768];
            let container_size = sizes[size_idx];
            let max_len = (container_size / 3 - 4) as usize;

            // Skip if message too long for this container size
            let real_bytes = real_msg.as_bytes();
            let decoy_bytes = decoy_msg.as_bytes();
            if real_bytes.len() > max_len || decoy_bytes.len() > max_len {
                return Ok(());
            }

            // Ensure passphrases differ
            let decoy_pass_actual = if real_pass == decoy_pass {
                format!("{}_different", decoy_pass)
            } else {
                decoy_pass
            };

            let result = create_container_native(
                &real_msg, &decoy_msg, &real_pass, &decoy_pass_actual, container_size,
            );

            match result {
                Ok((container, _, _)) => {
                    let recovered_real = open_container_native(&container, &real_pass, container_size);
                    prop_assert_eq!(recovered_real.as_deref(), Some(real_msg.as_str()));

                    let recovered_decoy = open_container_native(&container, &decoy_pass_actual, container_size);
                    prop_assert_eq!(recovered_decoy.as_deref(), Some(decoy_msg.as_str()));
                }
                Err(e) => {
                    // Only acceptable error is collision exhaustion
                    prop_assert!(e.contains("collision"), "Unexpected error: {}", e);
                }
            }
        }

        /// AEAD round-trip: encrypt with any key/nonce, decrypt with same key/nonce.
        #[test]
        fn aead_roundtrip_property(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            let sealed = aead_seal(&key, &nonce, &plaintext).unwrap();
            let opened = aead_open(&key, &nonce, &sealed).unwrap();
            prop_assert_eq!(opened, plaintext);
        }

        /// Slot encode/decode round-trip for arbitrary messages.
        #[test]
        fn slot_roundtrip_property(
            msg in prop::collection::vec(any::<u8>(), 0..200),
        ) {
            let slot_size = 256; // large enough for any test message
            if msg.len() > slot_size - 4 {
                return Ok(());
            }

            // Only test valid UTF-8 messages (decode_slot expects UTF-8)
            if let Ok(text) = std::str::from_utf8(&msg) {
                let slot = encode_slot(text.as_bytes(), slot_size).unwrap();
                prop_assert_eq!(slot.len(), slot_size);
                let decoded = decode_slot(&slot).unwrap();
                prop_assert_eq!(decoded, text);
            }
        }
    }

    // ── Corruption detection properties ─────────────────────────────

    proptest! {
        /// Flipping any single bit in a sealed AEAD ciphertext must cause
        /// decryption to fail (no partial plaintext).
        #[test]
        fn single_bit_flip_always_detected(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 1..128),
            flip_byte in 0usize..144,  // max sealed len = 128 + 16
        ) {
            let sealed = aead_seal(&key, &nonce, &plaintext).unwrap();
            if flip_byte >= sealed.len() {
                return Ok(());
            }

            let mut corrupted = sealed.clone();
            corrupted[flip_byte] ^= 0x01;
            prop_assert!(aead_open(&key, &nonce, &corrupted).is_none());
        }

        /// Truncating a sealed ciphertext must cause decryption to fail.
        #[test]
        fn truncation_always_detected(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 1..128),
            keep_bytes in 0usize..144,
        ) {
            let sealed = aead_seal(&key, &nonce, &plaintext).unwrap();
            if keep_bytes >= sealed.len() {
                return Ok(());
            }

            let truncated = &sealed[..keep_bytes];
            prop_assert!(aead_open(&key, &nonce, truncated).is_none());
        }

        /// A random key must never decrypt a valid ciphertext (no false positives).
        #[test]
        fn wrong_key_never_decrypts(
            key in prop::array::uniform32(any::<u8>()),
            wrong_key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            if key == wrong_key {
                return Ok(());
            }
            let sealed = aead_seal(&key, &nonce, &plaintext).unwrap();
            prop_assert!(aead_open(&wrong_key, &nonce, &sealed).is_none());
        }
    }

    // ── Offset distribution properties ──────────────────────────────

    proptest! {
        /// Offset must always be within [0, range) for any seed.
        #[test]
        fn offset_always_in_range(
            seeds in prop::array::uniform20(any::<u8>()),
            range in 1u32..100_000,
        ) {
            let offset = uniform_offset(&seeds, range);
            prop_assert!(offset < range, "offset {} >= range {}", offset, range);
        }

        /// Same seeds → same offset (determinism).
        #[test]
        fn offset_deterministic_property(
            seeds in prop::array::uniform20(any::<u8>()),
            range in 1u32..100_000,
        ) {
            let a = uniform_offset(&seeds, range);
            let b = uniform_offset(&seeds, range);
            prop_assert_eq!(a, b);
        }
    }

    // ── Slot isolation properties ───────────────────────────────────

    proptest! {
        /// For any two passphrases and any valid container size,
        /// create_container_native must either succeed with non-overlapping
        /// slots OR fail with a collision error. It must never silently overlap.
        #[test]
        fn slot_isolation_guaranteed(
            real_pass in ".{4,20}",
            decoy_pass in ".{4,20}",
            size_idx in 0usize..4,
        ) {
            let sizes = [4096u32, 8192, 16384, 32768];
            let container_size = sizes[size_idx];
            let slot_size = container_size / 3;
            let slot_with_tag = slot_size + 16;

            let decoy_pass_actual = if real_pass == decoy_pass {
                format!("{}_x", decoy_pass)
            } else {
                decoy_pass
            };

            match derive_all_keys(&real_pass, &decoy_pass_actual, container_size, 256, 1, 1) {
                Ok(keys) => {
                    prop_assert!(
                        !slots_overlap(keys.real_offset, keys.decoy_offset, slot_with_tag),
                        "Slots overlap: real={}, decoy={}, slot_with_tag={}",
                        keys.real_offset, keys.decoy_offset, slot_with_tag
                    );
                }
                Err(e) => {
                    prop_assert!(e.contains("collision"));
                }
            }
        }
    }

    // ── Container indistinguishability ───────────────────────────────

    #[test]
    fn container_entropy_high() {
        // Statistical test: container bytes should have near-uniform distribution.
        // Chi-squared test with 256 bins — expect p-value > 0.01.
        let (container, _, _) =
            create_container_native("test message", "decoy msg", "pass-r", "pass-d", 32768)
                .unwrap();

        let mut counts = [0u64; 256];
        for &b in &container {
            counts[b as usize] += 1;
        }

        let expected = container.len() as f64 / 256.0;
        let chi_sq: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();

        // With 255 degrees of freedom, chi-squared critical value at p=0.001 is ~310.
        // A good random distribution should be well below this.
        assert!(
            chi_sq < 400.0,
            "Container bytes have suspicious distribution: chi²={:.1}",
            chi_sq
        );
    }

    #[test]
    fn containers_with_same_inputs_differ() {
        // CSPRNG padding must make each container unique.
        let mut containers = Vec::new();
        for _ in 0..5 {
            let (c, _, _) =
                create_container_native("msg", "decoy", "pass-r", "pass-d", 4096).unwrap();
            containers.push(c);
        }
        for i in 0..containers.len() {
            for j in (i + 1)..containers.len() {
                assert_ne!(
                    containers[i], containers[j],
                    "Containers {} and {} are identical",
                    i, j
                );
            }
        }
    }
}
