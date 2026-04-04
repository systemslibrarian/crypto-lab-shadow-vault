# Shadow Vault — Security Invariants

This document defines the strict security invariants that MUST hold for all code paths. Each invariant includes: rationale, test strategy, and failure consequences.

---

## INV-1: No Partial Plaintext on Failure

**Statement:** A wrong passphrase, corrupted container, or malformed input MUST NEVER produce any plaintext bytes. AEAD decryption either fully succeeds (tag verifies) or fully fails (zero bytes returned).

**Why it matters:** Partial plaintext leaks information about the message content. In a deniable encryption system, even a single leaked byte can reveal that additional data exists beyond the decoy.

**How to test:**
- Unit: `aead_wrong_key_fails`, `aead_wrong_nonce_fails`, `aead_corrupted_ciphertext_fails`, `aead_corrupted_tag_fails`
- Property: For random key/nonce/ciphertext triples, `aead_open` returns `None` with overwhelming probability
- Integration: Feed corrupted `.bin` files to the decrypt UI; verify only "No message found" is shown

**Failure consequence:** Plaintext oracle — adversary can extract message content byte-by-byte.

---

## INV-2: Indistinguishable Failure

**Statement:** All failure modes — wrong passphrase, corrupted ciphertext, truncated container, invalid UTF-8, wrong size parameter — MUST produce identical `{success: false}` responses with no distinguishing error messages, HTTP status codes, or timing metadata.

**Why it matters:** Distinct error messages create an oracle. An adversary who can distinguish "wrong passphrase" from "corrupted data" learns whether the container is valid, breaking deniability.

**How to test:**
- Unit: Compare error responses from wrong-passphrase, flip-bit, truncation, all-zeros, all-ones
- UI: Verify the same "No message found for this passphrase." string appears for all failure cases
- Timing: Measure wall-clock time for failure vs. success; both should run at least 1 Argon2id derivation

**Failure consequence:** Format oracle — adversary can confirm a file is a Shadow Vault container.

---

## INV-3: No Structural Markers

**Statement:** A container MUST have no headers, magic bytes, version fields, length prefix, or any fixed byte pattern at any offset. The container MUST be statistically indistinguishable from CSPRNG output.

**Why it matters:** Any fixed structure lets an adversary identify Shadow Vault files by scanning, which defeats plausible deniability. The container should look like random noise, a LUKS padding block, or any other random blob.

**How to test:**
- Unit: `container_is_full_size`, `independent_containers_differ`
- Statistical: Run chi-squared test on container bytes; entropy should be ~8.0 bits/byte
- Property: Two containers with the same inputs MUST differ (CSPRNG padding guarantees this)

**Failure consequence:** File identification — adversary can scan for Shadow Vault containers.

---

## INV-4: Slot Isolation

**Statement:** The REAL and DECOY encrypted slots MUST NOT overlap in the container byte space. Collision resolution guarantees this or aborts container creation.

**Why it matters:** Overlapping writes corrupt both ciphertexts. The second write partially overwrites the first, destroying AEAD integrity for one message and potentially creating a detectable pattern.

**How to test:**
- Unit: `container_slots_do_not_overlap`, `derive_all_keys_succeeds`
- Property: For random passphrase pairs and all container sizes, verify `|real_offset - decoy_offset| >= slot_size + 16`
- Exhaust: Test collision resolution with known-colliding passphrases

**Failure consequence:** Data corruption — one or both messages become unrecoverable.

---

## INV-5: Deterministic Derivation

**Statement:** The same (passphrase, role, Argon2id parameters, collision_counter) tuple MUST always produce identical (key, nonce, offset_seeds, offset).

**Why it matters:** Non-deterministic derivation makes containers unopenable. Decryption relies on re-deriving the exact same key material that was used during encryption.

**How to test:**
- Unit: `key_derivation_deterministic`, `salt_is_deterministic`, `uniform_offset_deterministic`
- Pinned: `pinned_vector_real_cc0`, `pinned_vector_decoy_cc0`, `pinned_vector_real_cc1`, `pinned_offset_calculation`
- Property: For any passphrase, `derive_key_material(p, r, m, i, par, cc) == derive_key_material(p, r, m, i, par, cc)`

**Failure consequence:** Data loss — containers become permanently unreadable.

---

## INV-6: Memory Zeroization on All Paths

**Statement:** All key material (keys, nonces, salts), plaintext slot buffers, Argon2id output, and intermediate cryptographic state MUST be zeroed via `zeroize` on every code path: success, failure, error, and panic.

**Why it matters:** Unreleased key material persists in WASM linear memory and can be recovered via heap inspection, core dumps, or memory forensics. In a deniable system, residual key material can prove the existence of a second message.

**How to test:**
- Code audit: Verify every `DerivedKeyMaterial`, `ResolvedKeys`, salt, and output buffer has a `Drop` impl or explicit `.zeroize()` call
- Structural: `derive_key_material` zeroes salt and output before return
- Structural: `create_container` zeroes slots, keys, and container copy
- Structural: `open_container` zeroes plaintext after `decode_slot`
- Structural: `derive_all_keys` zeroes discarded material during collision resolution AND on error return

**Known limitation:** JavaScript strings (passphrases, messages) are immutable and GC-managed. They cannot be securely zeroed. This is an inherent browser limitation documented in THREAT_MODEL.md §2.2.

**Failure consequence:** Key recovery — adversary with memory access can extract keys and decrypt both messages.

---

## INV-7: Container Size Validation

**Statement:** Only the sizes `[4096, 8192, 16384, 32768]` are valid. Implementations MUST reject any other size at both encrypt and decrypt boundaries.

**Why it matters:** Arbitrary container sizes could produce slot arithmetic that allows out-of-bounds reads/writes, or create containers where slot isolation cannot be guaranteed.

**How to test:**
- Unit: `container_all_valid_sizes`, `container_wrong_size_parameter_fails`
- Boundary: Test sizes 0, 1, 4095, 4097, 32769, u32::MAX
- JS layer: `VALID_CONTAINER_SIZES` whitelist in `vault.ts` and validation in `uploadContainer()`

**Failure consequence:** Memory safety violation or weakened cryptographic guarantees.

---

## INV-8: AEAD Authentication Covers Full Slot

**Statement:** The Poly1305 tag authenticates the *entire* sealed slot (ciphertext + length prefix + padding), not just the message bytes. The AAD `shadow-vault:v1` is included in authentication.

**Why it matters:** If only the message is authenticated, an adversary could modify the padding or length prefix to create a valid-looking container with different content.

**How to test:**
- Unit: `aead_ciphertext_includes_16_byte_tag`
- Unit: Verify `sealed.len() == slot_size + 16` for all slot sizes
- Corruption: Flip bits in padding region → verify decrypt fails

**Failure consequence:** Ciphertext malleability — adversary can modify non-authenticated bytes.

---

## INV-9: CSPRNG Quality

**Statement:** All random bytes (container fill, slot padding) MUST come from a CSPRNG (`getrandom` → `crypto.getRandomValues` in browser). Deterministic or low-entropy randomness MUST NOT be used.

**Why it matters:** If padding is predictable, the container has identifiable patterns that break INV-3 (no structural markers). The container would no longer be indistinguishable from random.

**How to test:**
- Code audit: Verify all `getrandom::fill()` calls
- Statistical: Run entropy tests on container byte distributions
- Unit: `independent_containers_differ` (same inputs produce different containers)

**Failure consequence:** Pattern analysis — adversary can identify padding vs. ciphertext regions.

---

## INV-10: Format Stability

**Statement:** All format-sensitive parameters (salt construction, AEAD algorithm/AAD, slot encoding, offset derivation, collision resolution) MUST remain unchanged. Any modification MUST fail the pinned test vectors.

**Why it matters:** Format changes silently break all existing containers. Users lose access to their encrypted data.

**How to test:**
- Pinned vectors: `pinned_vector_real_cc0`, `pinned_vector_decoy_cc0`, `pinned_vector_real_cc1`, `pinned_offset_calculation`
- Locked constants: `aad_value_locked`, `max_collision_counter_locked`, `max_message_length_formula`
- Salt stability: `salt_derivation_stability`

**Failure consequence:** Silent data loss — previously created containers become unreadable.
