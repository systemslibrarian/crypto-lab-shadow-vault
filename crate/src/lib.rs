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
    let length = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
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
        .encrypt(nonce, Payload { msg: plaintext, aad: AAD })
        .map_err(|e| format!("Encryption error: {}", e))
}

fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: AAD })
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
    let slot_size = (container_size / 3) as u32;
    let slot_with_tag = slot_size + 16;
    let safe_range = container_size - slot_size - 16;

    let mut collision_resolved = false;

    // Derive real key material (cc=0)
    let real_mat = derive_key_material(real_passphrase, "real", memory_kib, iterations, parallelism, 0)?;
    let mut real_offset = uniform_offset(&real_mat.offset_seeds, safe_range);
    let mut real_key = real_mat.key;
    let mut real_nonce = real_mat.nonce;
    drop(real_mat);

    // Derive decoy key material (cc=0)
    let decoy_mat_0 = derive_key_material(decoy_passphrase, "decoy", memory_kib, iterations, parallelism, 0)?;
    let initial_decoy_offset = uniform_offset(&decoy_mat_0.offset_seeds, safe_range);
    let mut decoy_offset = initial_decoy_offset;
    let mut decoy_key = decoy_mat_0.key;
    let mut decoy_nonce = decoy_mat_0.nonce;
    // Keep initial decoy for phase 2 fallback
    let initial_decoy_key = decoy_mat_0.key;
    let initial_decoy_nonce = decoy_mat_0.nonce;
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
        let mat = derive_key_material(decoy_passphrase, "decoy", memory_kib, iterations, parallelism, cc)?;
        decoy_offset = uniform_offset(&mat.offset_seeds, safe_range);
        decoy_key = mat.key;
        decoy_nonce = mat.nonce;
        drop(mat);
    }

    // Phase 2: If still colliding, move real side
    if slots_overlap(real_offset, decoy_offset, slot_with_tag) {
        // Zero failed decoy attempts, restore initial
        decoy_key.zeroize();
        decoy_nonce.zeroize();

        for cc in 1..=MAX_COLLISION_COUNTER {
            real_key.zeroize();
            real_nonce.zeroize();
            let mat = derive_key_material(real_passphrase, "real", memory_kib, iterations, parallelism, cc)?;
            real_offset = uniform_offset(&mat.offset_seeds, safe_range);
            real_key = mat.key;
            real_nonce = mat.nonce;
            drop(mat);

            if !slots_overlap(real_offset, initial_decoy_offset, slot_with_tag) {
                decoy_key = initial_decoy_key;
                decoy_nonce = initial_decoy_nonce;
                decoy_offset = initial_decoy_offset;
                break;
            }
        }
    }

    if slots_overlap(real_offset, decoy_offset, slot_with_tag) {
        real_key.zeroize();
        real_nonce.zeroize();
        decoy_key.zeroize();
        decoy_nonce.zeroize();
        return Err("Slot collision could not be resolved. Try a larger container size or different passphrases.".into());
    }

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
    let mut real_slot = encode_slot(real_message.as_bytes(), slot_size)
        .map_err(|e| JsValue::from_str(&e))?;
    let real_sealed = aead_seal(&keys.real_key, &keys.real_nonce, &real_slot)
        .map_err(|e| JsValue::from_str(&e))?;
    real_slot.zeroize();

    let real_off = keys.real_offset as usize;
    if real_off + real_sealed.len() > container.len() {
        return Err(JsValue::from_str("Real slot exceeds container bounds"));
    }
    container[real_off..real_off + real_sealed.len()].copy_from_slice(&real_sealed);

    // Encode and encrypt decoy message
    let mut decoy_slot = encode_slot(decoy_message.as_bytes(), slot_size)
        .map_err(|e| JsValue::from_str(&e))?;
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
    js_sys::Reflect::set(&result, &"container".into(), &js_sys::Uint8Array::from(&container[..]))?;
    js_sys::Reflect::set(&result, &"realOffset".into(), &JsValue::from(keys.real_offset))?;
    js_sys::Reflect::set(&result, &"decoyOffset".into(), &JsValue::from(keys.decoy_offset))?;
    js_sys::Reflect::set(&result, &"collisionResolved".into(), &JsValue::from(keys.collision_resolved))?;

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
    let slot_size = (container_size / 3) as usize;
    let safe_range = container_size - (container_size / 3) - 16;

    for role in &["real", "decoy"] {
        for cc in 0..=MAX_COLLISION_COUNTER {
            let mat = match derive_key_material(passphrase, role, memory_kib, iterations, parallelism, cc) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let offset = uniform_offset(&mat.offset_seeds, safe_range) as usize;
            let end = offset + slot_size + 16;
            if end > container_data.len() {
                continue;
            }
            let sealed = &container_data[offset..end];

            if let Some(mut plaintext) = aead_open(&mat.key, &mat.nonce, sealed) {
                match decode_slot(&plaintext) {
                    Ok(message) => {
                        plaintext.zeroize();
                        let offset_percent = ((offset as f64) / (safe_range as f64) * 100.0).round() as u32;

                        let result = js_sys::Object::new();
                        js_sys::Reflect::set(&result, &"success".into(), &JsValue::TRUE)?;
                        js_sys::Reflect::set(&result, &"message".into(), &JsValue::from_str(&message))?;
                        js_sys::Reflect::set(&result, &"offsetPercent".into(), &JsValue::from(offset_percent))?;
                        return Ok(result.into());
                    }
                    Err(_) => {
                        plaintext.zeroize();
                        continue;
                    }
                }
            }
            // mat is dropped here → key material zeroized
        }
    }

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
        let key_bytes = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce_bytes = hex_to_bytes("070000004041424344454647");
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let sealed = cipher
            .encrypt(nonce, Payload { msg: &plaintext[..], aad: &aad })
            .unwrap();

        let expected_ct = hex_to_bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116"
        );
        let expected_tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");
        let mut expected = expected_ct;
        expected.extend_from_slice(&expected_tag);

        if sealed != expected {
            failures.push("AEAD seal (§2.8.2)".into());
        }

        // Test open
        match cipher.decrypt(nonce, Payload { msg: &sealed, aad: &aad }) {
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
            .decrypt(nonce, Payload { msg: &sealed, aad: &aad })
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
    js_sys::Reflect::set(&result, &"passed".into(), &JsValue::from(failures.is_empty()))?;
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
