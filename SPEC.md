# Shadow Vault — Container Format Specification

**Version:** 1  
**Format identifier:** `shadow-vault:v1` (used as AEAD AAD and salt prefix)

This document defines the container format, key derivation rules, slot layout, collision resolution protocol, and compatibility guarantees. These rules are enforced by 65+ automated tests including pinned deterministic test vectors.

---

## 1. Container Structure

A Shadow Vault container is a fixed-size block of bytes. It has no headers, no magic bytes, no length fields, and no structural markers. The entire container is indistinguishable from uniformly random data.

### Valid container sizes

| Size | Bytes |
|------|-------|
| 4 KB | 4096 |
| 8 KB | 8192 |
| 16 KB | 16384 |
| 32 KB | 32768 |

No other sizes are valid. Containers must be exactly one of these sizes.

### Construction

1. Allocate `container_size` bytes
2. Fill entirely with CSPRNG output (`getrandom`)
3. Derive keys, nonces, and offsets for both messages (see §2)
4. Encrypt and write the real message slot at its derived offset
5. Encrypt and write the decoy message slot at its derived offset
6. The result overwrites random data — remaining bytes stay random

---

## 2. Key Derivation

Each passphrase independently derives 64 bytes of key material via Argon2id.

### Salt construction

```
collision_counter == 0:  SHA-256("shadow-vault:v1:{role}")
collision_counter > 0:   SHA-256("shadow-vault:v1:{role}:c{collision_counter}")
```

Where `role` is either `"real"` or `"decoy"`.

The salt is always 32 bytes (the full SHA-256 output).

### Argon2id parameters

| Parameter | Field |
|-----------|-------|
| Algorithm | Argon2id |
| Version | 0x13 (19) |
| Memory | User-configured (KiB), default 65536 (64 MB) |
| Iterations | User-configured, default 3 |
| Parallelism | User-configured, default 4 |
| Output length | 64 bytes |

### Output layout

The 64-byte Argon2id output is split deterministically:

| Bytes | Purpose | Size |
|-------|---------|------|
| `[0..32)` | ChaCha20-Poly1305 key | 32 bytes |
| `[32..44)` | ChaCha20-Poly1305 nonce | 12 bytes |
| `[44..64)` | Offset seed material | 20 bytes |

---

## 3. Offset Derivation

The slot offset determines where in the container the encrypted message is written.

### Safe range

```
slot_size  = container_size / 3        (integer division)
safe_range = container_size - slot_size - 16
```

The offset must satisfy: `offset + slot_size + 16 <= container_size`.

### Rejection sampling

The 20 bytes of offset seed material are interpreted as five 32-bit little-endian candidates:

```
for i in 0..5:
    seed = u32_le(offset_seeds[i*4 .. i*4+4])
    limit = u32::MAX - (u32::MAX % range)
    if seed < limit:
        return seed % range
```

If all five candidates are rejected (probability < 2^-32), the first candidate is used with simple modulo (bias is negligible at this probability).

This produces a uniformly distributed offset in `[0, safe_range)`.

---

## 4. Slot Layout

### Message encoding

Each message slot is `slot_size` bytes:

| Bytes | Content |
|-------|---------|
| `[0..4)` | Message length as u32 little-endian |
| `[4..4+length)` | UTF-8 message bytes |
| `[4+length..slot_size)` | CSPRNG random padding |

Maximum message length: `slot_size - 4` bytes.

### AEAD encryption

Each encoded slot is encrypted with ChaCha20-Poly1305:

- **Key:** 32 bytes from derivation output `[0..32)`
- **Nonce:** 12 bytes from derivation output `[32..44)`
- **AAD:** The literal bytes `shadow-vault:v1` (15 bytes)
- **Plaintext:** The encoded slot (`slot_size` bytes)
- **Output:** Ciphertext + 16-byte Poly1305 tag = `slot_size + 16` bytes

The sealed output (ciphertext + tag) is written to the container at the derived offset.

---

## 5. Collision Resolution

If two slots overlap (their byte ranges intersect), a two-phase collision resolution protocol re-derives key material with incrementing collision counters.

### Overlap check

```
slots_overlap = |offset_a - offset_b| < slot_with_tag
where slot_with_tag = slot_size + 16
```

### Phase 1: Re-derive decoy

For `collision_counter` in `1..=7`:
1. Re-derive decoy key material with `collision_counter`
2. Compute new decoy offset
3. If no overlap: use the new decoy key/nonce/offset — done

### Phase 2: Re-derive real

If phase 1 exhausts all 7 counters without resolution:
1. Restore decoy to initial (cc=0) key material
2. For `collision_counter` in `1..=7`:
   - Re-derive real key material with `collision_counter`
   - Compute new real offset
   - If no overlap with initial decoy offset: done

### Maximum collision counter

`MAX_COLLISION_COUNTER = 7`

If both phases fail (15 total re-derivations), container creation fails with an error. This is statistically extremely unlikely for any container size ≥ 4096.

---

## 6. Decryption (Open)

To open a container, the implementation tries all `(role, collision_counter)` combinations:

```
for role in ["real", "decoy"]:
    for cc in 0..=7:
        derive key material with (passphrase, role, cc)
        compute offset
        extract sealed bytes at offset (slot_size + 16 bytes)
        attempt AEAD decrypt
        if success:
            decode slot → return message
```

This means each passphrase requires up to 16 Argon2id derivations in the worst case (2 roles × 8 collision counters).

A wrong passphrase produces no AEAD authentication match and returns `{success: false}`. The failure is indistinguishable from a corrupted container.

---

## 7. Security Invariants

These properties are tested and must hold for all valid containers:

1. **No partial decryption.** A wrong passphrase never produces partial plaintext. AEAD authentication either fully succeeds or fully fails.

2. **No structural markers.** The container has no headers, magic bytes, version fields, or any byte pattern that distinguishes it from random data.

3. **Slot isolation.** The real and decoy slots never overlap. Collision resolution guarantees this or fails creation.

4. **Deterministic derivation.** The same passphrase, role, parameters, and collision counter always produce identical key material.

5. **Clean failure.** Wrong passphrases, corrupted containers, and malformed inputs all produce the same generic failure response.

6. **Memory zeroing.** All key material, nonces, salts, plaintext slots, and intermediate buffers are zeroed via `zeroize` on drop and explicitly before function return.

---

## 8. Compatibility Rules

### What is format-sensitive

Any change to the following breaks all existing containers:

- Salt construction string format
- Argon2id algorithm, version, or output length
- Output byte layout (key/nonce/offset split points)
- Offset rejection sampling algorithm
- Slot encoding (length prefix format)
- AEAD algorithm or AAD value
- Collision counter range or resolution order

### What is NOT format-sensitive

These can change without breaking compatibility:

- Default Argon2id parameter values (memory, iterations, parallelism)
- Valid container size list (additions only — never remove a supported size)
- UI behavior, error messages, timing
- Worker/WASM bridge implementation

### Test vector enforcement

Format compatibility is enforced by pinned hex test vectors in the Rust test suite. These test exact key, nonce, and offset values for known inputs. If any test vector fails, the format has broken.

---

## 9. Reference Test Vectors

### Inputs (all vectors)

```
passphrase:  "test-vector-passphrase"
memory:      256 KiB
iterations:  1
parallelism: 1
```

### Vector 1: role="real", collision_counter=0

```
salt_input: "shadow-vault:v1:real"
key:          613d5144a8be8d5ab21ba284f8f3afc039c8c61f80f7f60c5f389c59f0812cfa
nonce:        a60ced6e00b20d75d50b4115
offset_seeds: 0ace1364f64fbceda90fd1ec451514af70af2457
offset (container_size=8192): 1392
```

### Vector 2: role="decoy", collision_counter=0

```
salt_input: "shadow-vault:v1:decoy"
key:          7ebce1e61141081d4c8ecf949877d3be1fc6b551c1946a38529c5abc662f906b
nonce:        bd66d48145f05ddfc0bdcb37
offset_seeds: e88c8e5707ea53c620c9d73bb479db69433ea7e7
offset (container_size=8192): 4950
```

### Vector 3: role="real", collision_counter=1

```
salt_input: "shadow-vault:v1:real:c1"
key:          59ea5d7c8395f6c64c49541edd64632a1fa5b9485337557212a8b27ca53d4edc
nonce:        4a98f94d381c84d61ef713ae
offset_seeds: 2b61a8306e2b0cdf55fd78f2a41556f498be6134
```

### AEAD reference

RFC 8439 §2.8.2 test vector is verified on every application load (self-test) and in the Rust test suite.
