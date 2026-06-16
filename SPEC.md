# Shadow Vault — Container Format Specification

**Version:** 1  
**Status:** Audit-ready draft  
**Format identifier:** `shadow-vault:v1` (used as AEAD AAD and salt prefix)  
**Normative RFCs:** [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) (ChaCha20-Poly1305)

This document is the authoritative definition of the Shadow Vault container format. All implementations MUST conform to this specification. Conformance is enforced by pinned deterministic test vectors and 75+ automated tests.

---

## 1. Overview

A Shadow Vault container stores two independently encrypted messages (designated *real* and *decoy*) in a single fixed-size binary blob. The container is designed to be:

- **Headerless:** No magic bytes, version fields, length prefixes, or structural markers.
- **Deniable:** Revealing one passphrase decrypts one message. The remaining bytes are indistinguishable from CSPRNG output.
- **Integrity-verified:** ChaCha20-Poly1305 AEAD ensures that any modification to ciphertext or tag is detected.

---

## 2. Container Structure

### 2.1 Valid Container Sizes

| Label | Size (bytes) | Slot size (bytes) | Max message (bytes) |
|-------|-------------|-------------------|---------------------|
| 4 KB  | 4096        | 1365              | 1361                |
| 8 KB  | 8192        | 2730              | 2726                |
| 16 KB | 16384       | 5461              | 5457                |
| 32 KB | 32768       | 10922             | 10918               |

No other sizes are valid. Implementations MUST reject containers whose length is not exactly one of these values.

### 2.2 Construction Algorithm

```
1. Allocate buffer B of exactly container_size bytes
2. Fill B entirely with CSPRNG output (crypto.getRandomValues / getrandom)
3. Derive key material for REAL slot  (§3)
4. Derive key material for DECOY slot (§3)
5. Resolve slot collisions if necessary (§6)
6. Encode REAL message into slot    (§4)
7. Encrypt REAL slot via AEAD       (§5)
8. Write sealed REAL bytes at derived offset into B
9. Encode DECOY message into slot   (§4)
10. Encrypt DECOY slot via AEAD      (§5)
11. Write sealed DECOY bytes at derived offset into B
12. Zeroize all intermediate key material, plaintext slots, and salts
13. Return B
```

**Ordering invariant:** The REAL slot is written first, then the DECOY slot. If slots overlap (which collision resolution prevents), the last write wins. This ordering is specified but irrelevant when collision resolution succeeds.

### 2.3 Random Fill Guarantee

After step 2, every byte of the container is CSPRNG output. Steps 8 and 11 overwrite specific ranges with AEAD ciphertext + tag. All remaining bytes retain their original random values. This ensures the container is indistinguishable from random data.

---

## 3. Key Derivation

Each passphrase independently derives 64 bytes of key material via Argon2id (RFC 9106).

### 3.1 Salt Construction

The salt is constructed deterministically from the role and optional collision counter:

```
collision_counter == 0:  salt = SHA-256("shadow-vault:v1:{role}")
collision_counter > 0:   salt = SHA-256("shadow-vault:v1:{role}:c{collision_counter}")
```

Where `{role}` is the literal string `"real"` or `"decoy"`, and `{collision_counter}` is the decimal string representation of the counter (e.g., `"1"`, `"2"`, ..., `"7"`).

The salt is always exactly 32 bytes (the full SHA-256 digest).

**Examples:**

| Input string | Hex salt (SHA-256) |
|---|---|
| `shadow-vault:v1:real` | SHA-256 of those bytes |
| `shadow-vault:v1:decoy` | SHA-256 of those bytes |
| `shadow-vault:v1:real:c1` | SHA-256 of those bytes |
| `shadow-vault:v1:decoy:c3` | SHA-256 of those bytes |

### 3.2 Argon2id Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Algorithm | Argon2id | MUST be Argon2id (hybrid) |
| Version | 0x13 (19) | MUST be version 19 |
| Memory | User-configured (KiB) | Default: 65536 (64 MB), Minimum: 16384 (16 MB) |
| Iterations | User-configured | Default: 3, Minimum: 2 |
| Parallelism | User-configured | Default: 4, Minimum: 1 |
| Output length | 64 bytes | MUST be exactly 64 bytes |

**Format-critical:** Changing the algorithm, version, or output length breaks all existing containers.

**Not format-critical:** Changing default parameter values does not break compatibility, but the *same* parameters used during creation MUST be used during opening. Parameters are not stored in the container.

**Boundary-enforced minimums (implementation requirement):** Both `create_container()` and `open_container()` MUST reject parameters below `memory_kib = 16384`, `iterations = 2`, `parallelism = 1` via `validate_argon2_params()`. These minimums are not part of the on-disk format — a container created under different parameters is still readable when the same parameters are supplied — but conforming implementations MUST enforce them at the trust boundary so a crafted Worker/WASM call cannot produce a trivially brute-forceable container. See [INVARIANTS.md](INVARIANTS.md) and [THREAT_MODEL.md](THREAT_MODEL.md) §1.3.

### 3.3 Output Layout

The 64-byte Argon2id output is split deterministically into three fields:

```
Bytes [0..32)   → ChaCha20-Poly1305 key      (32 bytes)
Bytes [32..44)  → ChaCha20-Poly1305 nonce     (12 bytes)
Bytes [44..64)  → Offset seed material        (20 bytes)
```

**Invariant:** These byte ranges MUST NOT change. Any change to the split points breaks all existing containers.

### 3.4 Zeroization Requirements

After key material is consumed:

1. The 64-byte Argon2id output buffer MUST be zeroed immediately after copying into the split fields.
2. The 32-byte salt MUST be zeroed immediately after the Argon2id call.
3. The `DerivedKeyMaterial` struct (key, nonce, offset_seeds) MUST be zeroed on drop.

---

## 4. Slot Encoding

### 4.1 Slot Size Calculation

```
slot_size = container_size / 3    (integer division, truncating)
```

| Container | slot_size | slot_size + 16 (sealed) |
|-----------|-----------|------------------------|
| 4096      | 1365      | 1381                   |
| 8192      | 2730      | 2746                   |
| 16384     | 5461      | 5477                   |
| 32768     | 10922     | 10938                  |

### 4.2 Message Encoding

Each message is encoded into a fixed-size slot:

```
Byte layout:
  [0..4)              → message length as u32 little-endian
  [4..4+length)       → UTF-8 message bytes
  [4+length..slot_size) → CSPRNG random padding
```

**Constraints:**

- `length` MUST be ≤ `slot_size - 4`.
- Message MUST be valid UTF-8.
- Padding MUST be filled with CSPRNG output (not zeros, not deterministic).

### 4.3 Maximum Message Length

```
max_message_length = slot_size - 4 = (container_size / 3) - 4
```

Messages exceeding this length MUST be rejected before encryption.

---

## 5. AEAD Encryption

### 5.1 Algorithm

ChaCha20-Poly1305 as specified in RFC 8439.

### 5.2 Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Key | 32 bytes | Argon2id output `[0..32)` |
| Nonce | 12 bytes | Argon2id output `[32..44)` |
| AAD | `shadow-vault:v1` (15 bytes, ASCII) | Hardcoded constant |
| Plaintext | Encoded slot (`slot_size` bytes) | §4.2 |

### 5.3 Output

```
sealed_output = ciphertext ‖ poly1305_tag
sealed_length = slot_size + 16 bytes
```

The 16-byte Poly1305 authentication tag is appended to the ciphertext (standard AEAD construction).

### 5.4 AAD Invariant

The AAD value `shadow-vault:v1` (the literal 15 ASCII bytes `73 68 61 64 6f 77 2d 76 61 75 6c 74 3a 76 31`) MUST NOT change. It is part of the format definition. Changing it breaks all existing containers.

---

## 6. Offset Derivation and Collision Resolution

### 6.1 Safe Range

```
safe_range = container_size - slot_size - 16
```

Any valid offset `o` satisfies: `o + slot_size + 16 ≤ container_size`.

### 6.2 Rejection Sampling

The 20 bytes of offset seed material are interpreted as five 32-bit little-endian candidates:

```
function uniform_offset(offset_seeds: [u8; 20], range: u32) -> u32:
    limit = u32::MAX - (u32::MAX % range)
    for i in 0..5:
        seed = u32_le(offset_seeds[i*4 .. i*4+4])
        if seed < limit:
            return seed % range
    // Fallback (probability < 2^-32 for any realistic range):
    return u32_le(offset_seeds[0..4]) % range
```

This produces a uniformly distributed offset in `[0, safe_range)`.

**Bias analysis:** The rejection limit ensures bias is at most `1/2^32` per candidate. With 5 candidates, the probability of fallback to biased modulo is `(u32::MAX % range / u32::MAX)^5`, which is negligible for all supported ranges.

### 6.3 Overlap Detection

Two slots overlap if their byte ranges intersect:

```
slot_with_tag = slot_size + 16
overlap = |offset_a - offset_b| < slot_with_tag
```

Note: This uses unsigned absolute difference cast to `u64` to avoid overflow.

### 6.4 Collision Resolution Protocol

If the REAL and DECOY slots overlap at their initial offsets (both with `collision_counter=0`):

**Phase 1 — Re-derive DECOY:**

```
for cc in 1..=7:
    re-derive DECOY key material with collision_counter = cc
    compute new DECOY offset
    if no overlap with REAL offset:
        use new DECOY key/nonce/offset → DONE
```

**Phase 2 — Re-derive REAL (if Phase 1 exhausted):**

```
save Phase 1 decoy key material (key, nonce, offset)
restore DECOY to initial (cc=0) key material
for cc in 1..=7:
    re-derive REAL key material with collision_counter = cc
    compute new REAL offset
    if no overlap with initial DECOY offset:
        use new REAL key/nonce/offset with initial DECOY → DONE

// Cross-phase fallback: Phase 2 real + Phase 1 decoy
if Phase 2 loop exhausted AND Phase 2 real offset ∩ Phase 1 decoy offset == ∅:
    use Phase 2 real key/nonce/offset with Phase 1 decoy key/nonce/offset → DONE
```

**Maximum collision counter:** `MAX_COLLISION_COUNTER = 7`

If both phases fail (15 total re-derivations, extremely unlikely), container creation MUST fail with an error. The implementation MUST NOT silently allow overlapping slots.

### 6.5 Collision Resolution Zeroization

During collision resolution:
- Each discarded `DerivedKeyMaterial` MUST be zeroed before the next derivation.
- If resolution fails, ALL accumulated key material MUST be zeroed before returning an error.

---

## 7. Decryption (Open) Algorithm

```
function open_container(container, passphrase, container_size, argon2_params):
    slot_size = container_size / 3
    safe_range = container_size - slot_size - 16

    // Phase 1: Derive ALL key materials (constant-time Argon2id phase)
    derivations = []
    for role in ["real", "decoy"]:
        for cc in 0..=MAX_COLLISION_COUNTER:
            material = derive_key_material(passphrase, role, argon2_params, cc)
            offset = uniform_offset(material.offset_seeds, safe_range)
            derivations.append((material, offset))

    // Phase 2: Check AEAD matches (microseconds per check)
    for (material, offset) in derivations:
        sealed = container[offset .. offset + slot_size + 16]
        plaintext = aead_open(material.key, material.nonce, sealed)
        if plaintext is Some:
            message = decode_slot(plaintext)
            zeroize(plaintext)
            if message is Ok:
                zeroize_all(derivations)
                return {success: true, message}

    zeroize_all(derivations)
    return {success: false}
```

**Enumeration order:** `["real", "decoy"]` × `[0, 1, 2, 3, 4, 5, 6, 7]` = 16 derivations always.

**Constant-time derivation:** ALL 16 Argon2id derivations are performed before any AEAD check. This eliminates timing side channels that could otherwise distinguish real vs. decoy roles or reveal the collision counter. AEAD checks are microseconds and do not contribute measurable timing variation.

---

## 8. Failure Model

### 8.1 Unified Failure Response

All failure modes produce the same output: `{success: false}`. No additional information is provided.

| Failure cause | Response | Distinguishable? |
|---------------|----------|-------------------|
| Wrong passphrase | `{success: false}` | No |
| Corrupted ciphertext | `{success: false}` | No |
| Corrupted tag | `{success: false}` | No |
| Truncated container | `{success: false}` | No |
| Invalid UTF-8 after decrypt | `{success: false}` | No |
| All-zeros container | `{success: false}` | No |
| Wrong container size parameter | `{success: false}` | No |

### 8.2 No Partial Plaintext

AEAD decryption either fully succeeds or fully fails. There is no mode where partial plaintext is returned. If the Poly1305 tag does not verify, the entire decryption is rejected.

### 8.3 Timing Properties

- **All paths:** Always perform exactly 16 Argon2id derivations (2 roles × 8 collision counters). Key material derivation is the dominant cost; AEAD checks are microseconds.
- **Constant time:** Success and failure paths have identical Argon2id timing. Neither the role (real vs. decoy) nor the collision counter is distinguishable from timing.
- **UX tradeoff:** With recommended parameters (64 MB, 3 iterations), each open attempt takes ~24s (16 × ~1.5s). This is the cost of timing-safe decryption.

---

## 9. Security Invariants

The following properties MUST hold for all valid containers. Each is enforced by automated tests.

### INV-1: No partial plaintext on failure

A wrong passphrase MUST NOT produce any plaintext bytes. AEAD authentication either fully succeeds or fully fails.

**Test coverage:** `aead_wrong_key_fails`, `aead_wrong_nonce_fails`, `aead_corrupted_ciphertext_fails`, `aead_corrupted_tag_fails`, `container_wrong_passphrase_returns_none`.

### INV-2: Indistinguishable failure

Wrong passphrase, corrupted container, truncated input, and invalid encoding MUST all produce identical `{success: false}` responses with no distinguishing metadata.

**Test coverage:** `single_bit_flip_detected`, `tag_bit_flip_detected`, `truncated_container_rejected`, `all_zeros_container_no_match`, `all_ones_container_no_match`, `many_passphrases_no_false_positive`.

### INV-3: No structural markers

The container MUST have no headers, magic bytes, version fields, or any byte pattern that distinguishes it from uniformly random data.

**Test coverage:** `independent_containers_differ`, `container_is_full_size`.

### INV-4: Slot isolation

The REAL and DECOY slots MUST NOT overlap. Collision resolution guarantees this or fails container creation.

**Test coverage:** `container_slots_do_not_overlap`, `derive_all_keys_succeeds`.

### INV-5: Deterministic derivation

The same passphrase, role, parameters, and collision counter MUST always produce identical key material.

**Test coverage:** `salt_is_deterministic`, `key_derivation_deterministic`, `uniform_offset_deterministic`, `pinned_vector_real_cc0`, `pinned_vector_decoy_cc0`, `pinned_vector_real_cc1`, `pinned_offset_calculation`.

### INV-6: Memory zeroization

All key material, nonces, salts, plaintext slots, and intermediate buffers MUST be zeroed via `zeroize` on all code paths (success, failure, error).

**Code evidence:** `DerivedKeyMaterial::Drop`, `ResolvedKeys::Drop`, explicit `.zeroize()` calls in `create_container()` and `open_container()`.

---

## 10. Compatibility Rules

### 10.1 Format-Sensitive (changes break existing containers)

Any change to the following constitutes a breaking format change and MUST bump the format version:

1. Salt construction string format or hash algorithm
2. Argon2id algorithm, version, or output length
3. Output byte layout (key/nonce/offset split points)
4. Offset rejection sampling algorithm
5. Slot encoding (length prefix format, endianness)
6. AEAD algorithm, mode, or AAD value
7. Collision counter range or resolution phase order
8. Slot size formula (`container_size / 3`)

### 10.2 Not Format-Sensitive

The following may change without breaking compatibility:

- Default Argon2id parameter values (memory, iterations, parallelism)
- Valid container size list (additions only — never remove a supported size)
- UI behavior, error messages, timing characteristics
- Worker/WASM bridge implementation
- CSP headers, build system, CI pipeline

### 10.3 Test Vector Enforcement

Format compatibility is enforced by pinned hex test vectors in the Rust test suite. These test exact key, nonce, offset seed, and offset values for known inputs. If any pinned test vector fails, the format has broken.

---

## 11. Reference Test Vectors

### Common Inputs

```
passphrase:  "test-vector-passphrase"
memory:      256 KiB
iterations:  1
parallelism: 1
```

### Vector 1: role="real", collision_counter=0

```
salt_input:    "shadow-vault:v1:real"
key:           613d5144a8be8d5ab21ba284f8f3afc039c8c61f80f7f60c5f389c59f0812cfa
nonce:         a60ced6e00b20d75d50b4115
offset_seeds:  0ace1364f64fbceda90fd1ec451514af70af2457
offset (cs=8192, safe_range=5446): 1392
```

### Vector 2: role="decoy", collision_counter=0

```
salt_input:    "shadow-vault:v1:decoy"
key:           7ebce1e61141081d4c8ecf949877d3be1fc6b551c1946a38529c5abc662f906b
nonce:         bd66d48145f05ddfc0bdcb37
offset_seeds:  e88c8e5707ea53c620c9d73bb479db69433ea7e7
offset (cs=8192, safe_range=5446): 4950
```

### Vector 3: role="real", collision_counter=1

```
salt_input:    "shadow-vault:v1:real:c1"
key:           59ea5d7c8395f6c64c49541edd64632a1fa5b9485337557212a8b27ca53d4edc
nonce:         4a98f94d381c84d61ef713ae
offset_seeds:  2b61a8306e2b0cdf55fd78f2a41556f498be6134
```

### AEAD Compliance

RFC 8439 §2.8.2 test vector is verified on every application load (browser self-test) and in the Rust CI test suite. See `rfc_8439_test_vector` test.

---

## 12. Notation and Definitions

| Term | Definition |
|------|-----------|
| **Container** | The complete fixed-size binary output |
| **Slot** | A fixed-size region holding one encoded message + random padding |
| **Sealed slot** | A slot after AEAD encryption (slot_size + 16 bytes) |
| **Offset** | The byte position within the container where a sealed slot begins |
| **Role** | Either `"real"` or `"decoy"` — determines the salt string |
| **Collision counter** | An integer 0–7 used to re-derive key material when slots overlap |
| **Safe range** | The range of valid offsets: `[0, container_size - slot_size - 16)` |
| **AAD** | Additional Authenticated Data: the constant `shadow-vault:v1` |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator |
