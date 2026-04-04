# Shadow Vault — Security Review Checklist

This checklist is for auditors, reviewers, and contributors evaluating the security posture of Shadow Vault. Each item references the relevant source file and test.

---

## 1. Cryptographic Correctness

- [ ] **Argon2id parameters match OWASP/RFC 9106 recommendations**
  - Default: 64 MB memory, 3 iterations, parallelism 4
  - File: [crate/src/lib.rs](crate/src/lib.rs) `derive_key_material()`
  - User-configurable via UI sliders (minimum 16 MB)

- [ ] **ChaCha20-Poly1305 uses correct AAD**
  - AAD is the literal bytes `shadow-vault:v1` (15 bytes)
  - File: [crate/src/lib.rs](crate/src/lib.rs) `const AAD`
  - Tests: `rfc8439_aead_test_vector`, `aead_round_trip`, `aead_wrong_key_fails`

- [ ] **RFC 8439 test vector passes**
  - §2.8.2 AEAD vector verified in `self_test()` and unit tests
  - Runs on every application load and in CI

- [ ] **Key material is 64 bytes, split correctly**
  - `[0..32)` = key, `[32..44)` = nonce, `[44..64)` = offset seeds
  - Tests: `pinned_vector_real_cc0`, `pinned_vector_decoy_cc0`, `pinned_vector_real_cc1`

- [ ] **Salt derivation is deterministic and role-separated**
  - SHA-256 of `"shadow-vault:v1:{role}"` or `"shadow-vault:v1:{role}:c{N}"`
  - Tests: `salt_is_deterministic`, `salt_differs_by_role`, `salt_differs_by_collision_counter`

---

## 2. Zeroization

- [ ] **`DerivedKeyMaterial` implements `Drop` with `zeroize()`**
  - File: [crate/src/lib.rs](crate/src/lib.rs) `impl Drop for DerivedKeyMaterial`
  - Zeroes `key`, `nonce`, `offset_seeds`

- [ ] **`ResolvedKeys` implements `Drop` with `zeroize()`**
  - File: [crate/src/lib.rs](crate/src/lib.rs) `impl Drop for ResolvedKeys`
  - Zeroes `real_key`, `real_nonce`, `decoy_key`, `decoy_nonce`

- [ ] **Argon2id output buffer is zeroed after split**
  - `output.zeroize()` called immediately after copying to `DerivedKeyMaterial`

- [ ] **Salt is zeroed after Argon2id call**
  - `salt.zeroize()` called after `hash_password_into()`

- [ ] **Plaintext slot buffers are zeroed after AEAD seal**
  - `real_slot.zeroize()` and `decoy_slot.zeroize()` in `create_container()`
  - `plaintext.zeroize()` in `open_container()` after `decode_slot()`

- [ ] **Container bytes are zeroed after JS extraction**
  - `container.zeroize()` at end of `create_container()`

- [ ] **Keys are explicitly zeroed before function return**
  - `keys.real_key.zeroize()` etc. at end of `create_container()`

- [ ] **Failed collision resolution zeroes all material**
  - Keys zeroed before returning error in `derive_all_keys()`

---

## 3. Container Format Integrity

- [ ] **Container is exactly the requested size**
  - Test: `container_is_full_size`

- [ ] **Container begins as 100% CSPRNG random bytes**
  - `getrandom::fill()` called before any slot writes
  - File: [crate/src/lib.rs](crate/src/lib.rs) `create_container()`

- [ ] **No headers, magic bytes, or structural markers**
  - Verified by manual inspection — no fixed bytes at any offset
  - Test: `all_zeros_container_no_match`, `all_ones_container_no_match`

- [ ] **Slot size = container_size / 3 (integer division)**
  - Test: `slot_layout_arithmetic`

- [ ] **Offset rejection sampling is uniform**
  - 5 candidates, 4-byte LE, rejection at `u32::MAX - (u32::MAX % range)`
  - Test: `uniform_offset_within_range`, `uniform_offset_deterministic`
  - Test: `pinned_offset_calculation`

- [ ] **Slots never overlap after collision resolution**
  - Two-phase protocol: decoy re-derive (cc 1–7), then real re-derive (cc 1–7)
  - Test: `collision_resolution_works`

---

## 4. Failure Indistinguishability

- [ ] **Wrong passphrase returns `{success: false}` — no detail**
  - File: [crate/src/lib.rs](crate/src/lib.rs) end of `open_container()`

- [ ] **Corrupted container returns `{success: false}` — no detail**
  - Tests: `single_bit_flip_detected`, `tag_bit_flip_detected`, `truncated_container_rejected`

- [ ] **UI error messages are identical for all failure types**
  - File: [src/ui/decrypt.ts](src/ui/decrypt.ts) — all failures show "No message found for this passphrase."

- [ ] **No timing side channel between success and failure**
  - Both paths derive keys (Argon2id dominates timing). Failure iterates all 16 combinations; success returns early but after ≥1 derivation.

---

## 5. Browser Security

- [ ] **Content Security Policy restricts all sources**
  - `default-src 'none'`; explicit allowlist for `script-src`, `worker-src`, `style-src`, `font-src`, `img-src`, `connect-src`
  - `form-action 'none'`; `frame-ancestors 'none'`
  - File: [index.html](index.html) `<meta http-equiv="Content-Security-Policy">`

- [ ] **Worker loads only self-hosted WASM**
  - File: [public/vault.worker.js](public/vault.worker.js) — imports from relative `./shadow_vault_crypto.js`

- [ ] **DOM inputs cleared after use**
  - Encrypt: passphrases and messages cleared after container creation
  - Decrypt: passphrase cleared after attempt
  - Files: [src/ui/encrypt.ts](src/ui/encrypt.ts), [src/ui/decrypt.ts](src/ui/decrypt.ts)

- [ ] **Auto-clear timer on decrypted messages**
  - 2-minute timer starts when message is displayed
  - Manual CLEAR button available
  - File: [src/ui/decrypt.ts](src/ui/decrypt.ts)

- [ ] **Idle cleanup (5-minute timeout)**
  - Clears all inputs and resets state
  - File: [src/main.ts](src/main.ts)

---

## 6. CI / Build Integrity

- [ ] **Rust tests run in CI before WASM build**
  - 65+ tests including pinned vectors, corruption, edge cases
  - File: [.github/workflows/deploy.yml](.github/workflows/deploy.yml) `cargo test --release`

- [ ] **TypeScript strict mode enforced**
  - `npx tsc --noEmit` in CI

- [ ] **No `eval()`, no dynamic script loading, no inline scripts**
  - CSP blocks these; code does not use them

- [ ] **WASM built from source in CI**
  - `wasm-pack build --target web --release`
  - No pre-built binaries committed

---

## 7. Deniability Guarantees

- [ ] **Container is indistinguishable from random data**
  - No magic bytes, no fixed offsets, no length fields
  - Full CSPRNG fill before slot writes

- [ ] **Single passphrase reveals exactly one message**
  - Each passphrase independently derives its own key/nonce/offset
  - No metadata connects the two slots

- [ ] **Identical passphrases are rejected**
  - UI validation prevents creating a container with identical passphrases
  - File: [src/ui/encrypt.ts](src/ui/encrypt.ts) `validateForm()`

- [ ] **Documentation is honest about limitations**
  - Modal, README, THREAT_MODEL.md all state this is a demonstration
  - VeraCrypt recommended for production use

---

## 8. Known Limitations

These are inherent design constraints that cannot be fixed without breaking changes:

- **Deterministic offsets across containers:** Same passphrases + same Argon2id params always produce the same slot offsets and key material. Reusing passphrases across multiple containers enables a two-time pad attack that reveals slot positions and XOR of plaintexts. **Mitigation:** Never reuse passphrases. See THREAT_MODEL.md §2.6.

- **Unicode normalization not performed:** Passphrases are passed as raw UTF-8 bytes. Different Unicode representations of the same visual character (NFC vs NFD) produce different Argon2id output, making containers potentially unopenable across platforms. **Mitigation:** Use ASCII-only passphrases. See THREAT_MODEL.md §2.7.

- **JavaScript string immutability:** Passphrases and messages enter as JavaScript strings which cannot be securely zeroed. The GC manages their lifetime. Defense-in-depth (input clearing, Worker cleanup) reduces exposure but cannot guarantee erasure. See THREAT_MODEL.md §2.2.

- **Google Fonts external dependency:** The CSP allows `fonts.googleapis.com` and `fonts.gstatic.com`. This creates a privacy/tracking vector. Fonts do not carry executable code but the CSS request reveals the user's IP address to Google. A fully offline deployment would need to self-host the fonts.

- **Clipboard not fully controlled:** The clipboard clear (30s after copy) uses `navigator.clipboard.writeText('')`. The OS clipboard may retain copies, and clipboard managers may archive the content before the clear fires.
