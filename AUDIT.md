# Shadow Vault Security Audit Report

**Date:** 2026-04-04  
**Auditor:** AI model (Claude Opus 4.6 via GitHub Copilot)  
**Commit audited:** `0594081`  
**Commit after fixes:** `c5ed55a`  
**Scope:** Full codebase — Rust/WASM core, TypeScript UI, Worker bridge, HTML, CSP, SPEC, THREAT_MODEL, SECURITY, CI

---

## Executive Summary

Shadow Vault's cryptographic core (Argon2id + ChaCha20-Poly1305 via RustCrypto) is correctly implemented with proper zeroization, AEAD authentication, and rejection sampling. The deniability model is fundamentally sound at the container level. Six findings were identified and fixed during this audit: one HIGH (timing side channel distinguishing real vs. decoy roles), two MEDIUM (missing input validation at the Rust boundary), and three LOW (defense-in-depth gaps). Five additional observations are documented as known limitations inherent to the headerless format and browser deployment model.

After fixes: no CRITICAL or HIGH findings remain unresolved. All 79 Rust tests pass. TypeScript compiles cleanly.

---

## Findings

### 🔴 CRITICAL

No critical findings.

---

### 🟠 HIGH

#### H-1: Timing side channel distinguishes real vs. decoy role

**File:** [crate/src/lib.rs](crate/src/lib.rs) — `open_container()` (lines 406–450)  
**Description:** `open_container` iterated role="real" (positions 1–8) before role="decoy" (positions 9–16), returning on first AEAD match. A correct real passphrase returned after ~1 Argon2id derivation (~1.5s); a correct decoy passphrase returned after ~9 derivations (~13.5s). A wrong passphrase always exhausted all 16 (~24s).  
**Attack scenario:** An adversary observing decryption timing under coercion can determine whether the revealed passphrase corresponds to the "real" or "decoy" role. If the user reveals the decoy passphrase and decryption takes ~13.5s instead of ~1.5s, the adversary concludes this is the decoy (derivation positions 9–16), proving a second slot exists. This breaks deniability.  
**Severity justification:** Directly breaks the core deniability property — the most important security guarantee of the system.  
**Fix applied:** Split `open_container` into two phases: (1) derive ALL 16 key materials upfront (constant Argon2id cost), (2) check AEAD matches in microseconds. All paths now perform exactly 16 Argon2id derivations regardless of outcome. UX tradeoff: correct passphrases now take ~24s instead of ~1.5s with default params.  
**Fix commit:** `0572c4c`  
**Test verified:** All 79 Rust tests pass. `open_container_native` updated to match.  
**Docs updated:** SPEC.md §7 (decryption algorithm), §8.3 (timing properties). THREAT_MODEL.md §2.3 (side-channel attacks).

---

### 🟡 MEDIUM

#### M-1: No container size validation in Rust

**File:** [crate/src/lib.rs](crate/src/lib.rs) — `create_container()`, `open_container()`  
**Description:** The Rust WASM functions accepted arbitrary `container_size` values. Only the JavaScript `uploadContainer()` validated sizes. A crafted Worker `postMessage` with `container_size=3` would cause arithmetic underflow in `slot_size - 4` (slot encoding), panicking the WASM module.  
**Attack scenario:** A malicious browser extension or XSS sends a crafted Worker message with `container_size=0` or `container_size=3`, causing a panic that crashes the crypto Worker. While the threat model (§2.1) places hostile in-page code out of scope, defense-in-depth requires the crypto boundary to validate its own inputs.  
**Severity justification:** Can cause denial of service (WASM panic). No key material leak, but the crypto boundary should not trust caller-supplied sizes.  
**Fix applied:** Added `VALID_CONTAINER_SIZES` constant and validation check at the top of `create_container()` and `open_container()`. Invalid sizes return an error instead of panicking. Added `create_container_rejects_invalid_size` and `valid_container_sizes_locked` tests.  
**Fix commit:** `fe3ed4c`  
**Test verified:** 79 tests pass (77 prior + 2 new).  
**Docs updated:** None needed — this is an implementation hardening, not a spec change.

#### M-2: No minimum Argon2id parameter enforcement in Rust

**File:** [crate/src/lib.rs](crate/src/lib.rs) — `create_container()`, `open_container()`  
**Description:** The HTML iteration slider had `min="1"` and `validateParams()` in TypeScript only returned warning strings — it did not prevent encryption. The Rust code accepted any params that `Params::new()` allowed (minimum: 8 KiB memory, 1 iteration). A crafted Worker message could set `memory_kib=8, iterations=1, parallelism=1`, making Argon2id run in microseconds and destroying brute-force resistance.  
**Attack scenario:** (1) A user manually sets the slider to iterations=1, ignores the warning, and creates a container with trivially brute-forceable key derivation. (2) A crafted Worker message bypasses even the slider minimum, using params far below OWASP/RFC 9106 recommendations.  
**Severity justification:** Weak key derivation collapses the deniability model — an adversary can brute-force both passphrases simultaneously.  
**Fix applied:** Added `validate_argon2_params()` in Rust enforcing `memory >= 16384 KiB`, `iterations >= 2`, `parallelism >= 1`. Called at the WASM boundary in both `create_container()` and `open_container()`. Fixed HTML slider: `min="1"` → `min="2"` for iterations.  
**Fix commit:** `fcd4c35`  
**Test verified:** 79 tests pass. Test suite uses lower params (256 KiB, 1 iter) which is allowed because tests call `derive_key_material()` directly, not the WASM-exported functions.  
**Docs updated:** None needed.

---

### 🔵 LOW

#### L-1: Self-test failure doesn't gate Worker operations

**File:** [public/vault.worker.js](public/vault.worker.js) — `startup()`  
**Description:** The Worker set `initialized = true` regardless of whether `self_test().passed` was true. The main thread UI disabled buttons on self-test failure, but a crafted `postMessage` could still trigger crypto operations via the Worker, bypassing the UI gate.  
**Attack scenario:** After a hypothetical AEAD implementation failure (e.g., corrupted WASM binary), a crafted Worker message could still invoke `create_container()` or `open_container()`, which would produce incorrect ciphertext.  
**Severity justification:** Low probability (requires AEAD self-test to fail, which would indicate a corrupted WASM binary — already a supply chain compromise). Defense-in-depth.  
**Fix applied:** Worker now sets `initialized = true` only if `self_test().passed === true`. All subsequent crypto commands are refused with "WASM not initialized" if self-test failed.  
**Fix commit:** `f2d95f4`  
**Test verified:** TypeScript compiles cleanly.  
**Docs updated:** None needed.

#### L-2: Unused dependencies increase attack surface

**File:** [crate/Cargo.toml](crate/Cargo.toml)  
**Description:** `serde`, `serde-wasm-bindgen`, and the `zeroize` `derive` feature were declared as dependencies but never used in `lib.rs`. JS interop uses `js_sys::Object/Reflect` directly. The `derive` feature (`#[derive(Zeroize)]`) is unused — `Drop` is implemented manually.  
**Attack scenario:** Unused transitive dependencies increase supply-chain attack surface. A compromised `serde` or `serde-wasm-bindgen` crate could inject malicious code into the WASM binary even though the application never calls into the crate.  
**Severity justification:** No immediate vulnerability, but every unused dependency is unnecessary risk.  
**Fix applied:** Removed `serde`, `serde-wasm-bindgen` from `[dependencies]`. Changed `zeroize = { version = "1", features = ["derive"] }` to `zeroize = "1"`.  
**Fix commit:** `d17c70a`  
**Test verified:** 79 tests pass. WASM binary is smaller.  
**Docs updated:** None needed.

#### L-3: Clipboard not cleared after copying decrypted message

**File:** [src/ui/decrypt.ts](src/ui/decrypt.ts) — `btnCopy` handler  
**Description:** The COPY button put decrypted plaintext on the system clipboard with `navigator.clipboard.writeText()` but never cleared it. The plaintext remained on the clipboard until the user manually copied something else, potentially for hours.  
**Attack scenario:** A user copies a decrypted message, switches to another application, and the message remains accessible via paste to any application. A clipboard manager could archive it permanently.  
**Severity justification:** Defense-in-depth. The clipboard API cannot guarantee erasure (OS/clipboard manager may retain copies), but clearing after 30 seconds removes the most obvious leak vector.  
**Fix applied:** Added `navigator.clipboard.writeText('')` called 30 seconds after copy, in a timeout with a `.catch()` to handle cases where clipboard access is revoked.  
**Fix commit:** `0990ddd`  
**Test verified:** TypeScript compiles cleanly.  
**Docs updated:** SECURITY.md §8 (Known Limitations — clipboard).

---

### ⚪ INFO

#### I-1: Collision counter reveals partial offset information (by design)

**File:** [crate/src/lib.rs](crate/src/lib.rs) — `derive_all_keys()`  
**Description:** If the decoy slot's collision counter is > 0, an attacker holding the decoy passphrase can determine that the decoy's original offset (cc=0) overlapped with the real slot. This narrows the real slot's position to a `2 × slot_with_tag` byte window around the decoy's cc=0 offset.  
**Attack scenario:** The attacker knows `|real_offset - decoy_cc0_offset| < slot_with_tag`. For 4 KB containers (slot_with_tag=1381, safe_range=2715), this narrows by ~50%. However, the attacker cannot exploit this without the real passphrase — the bytes at any offset are random/ciphertext.  
**Severity justification:** INFO. The information is theoretically leaked but not actionable without the real passphrase. This is an inherent property of the collision resolution protocol and cannot be eliminated without storing additional metadata (which breaks the headerless format).

#### I-2: Deterministic offsets create two-time pad across containers

**File:** [crate/src/lib.rs](crate/src/lib.rs) — `derive_key_material()`  
**Description:** Same (passphrase, role, Argon2id params) → same (key, nonce, offset). Two containers with the same passphrases share identical key/nonce pairs, creating a classic two-time pad. XOR of the two containers at the deterministic offset reveals XOR of the two plaintexts, with leading zeros if the same message was encrypted.  
**Attack scenario:** Adversary with two containers and one passphrase can confirm the second slot's existence and position, breaking deniability for all containers sharing those passphrases.  
**Severity justification:** INFO. This is an inherent design limitation of the headerless format — there's no space to store per-container randomness. Already documented in THREAT_MODEL.md §2.6 (updated with explicit two-time pad description).

#### I-3: No Unicode normalization on passphrases

**File:** [crate/src/lib.rs](crate/src/lib.rs) — `derive_key_material()` uses `passphrase.as_bytes()`  
**Description:** Passphrases are passed as raw UTF-8 bytes. `é` (U+00E9, NFC, 2 bytes) and `é` (U+0065 U+0301, NFD, 3 bytes) produce different Argon2id outputs, making containers potentially unopenable across platforms.  
**Severity justification:** INFO. Cross-platform portability issue, not a security vulnerability. Documented in THREAT_MODEL.md §2.7 and SECURITY.md §8.

#### I-4: Google Fonts external dependency — RESOLVED

**File:** [index.html](index.html), [src/main.ts](src/main.ts)  
**Description:** Previously the CSP allowed `fonts.googleapis.com` (CSS) and `fonts.gstatic.com` (fonts), letting Google log IP addresses of users accessing the tool.  
**Resolution:** Fonts are now bundled from `@fontsource` and served same-origin. The external font origins were removed from the CSP (`style-src` and `font-src` are now `'self'` only), and the `<link>`/`preconnect` tags were deleted. The app makes no third-party requests and works fully offline.  
**Severity justification:** INFO (privacy/tracking). Now eliminated.

#### I-5: `unsafe-inline` in `style-src` CSP directive

**File:** [index.html](index.html) — CSP meta tag  
**Description:** `style-src 'self' 'unsafe-inline'` allows inline styles. This is required by Vite/Tailwind's build pipeline and runtime style injection.  
**Severity justification:** INFO. `unsafe-inline` for styles is standard for Tailwind-based applications. It does not affect `script-src` which is correctly restricted to `'self' 'wasm-unsafe-eval'`.

---

## Verified Properties

The following security properties were verified correct in the code — no fix needed:

1. **Container is 100% CSPRNG before slot writes.** `getrandom::fill()` fills the full container before any encrypted data is written. Verified in `create_container()`.

2. **No structural markers.** No magic bytes, headers, version fields, or fixed patterns at any offset. Verified by `container_is_full_size`, `independent_containers_differ`, chi-squared test in `container_entropy_high`.

3. **Salt construction matches SPEC §3.1.** `derive_salt()` correctly produces `SHA-256("shadow-vault:v1:{role}")` for cc=0 and `SHA-256("shadow-vault:v1:{role}:c{cc}")` for cc>0. Verified by `salt_derivation_stability` against expected SHA-256 output.

4. **Argon2id version is V0x13 (19).** Explicitly set via `Version::V0x13`. Verified in code.

5. **Output split is correct.** `[0..32)` = key, `[32..44)` = nonce, `[44..64)` = offset seeds. Verified by pinned test vectors: `pinned_vector_real_cc0`, `pinned_vector_decoy_cc0`, `pinned_vector_real_cc1`, `pinned_offset_calculation`.

6. **AAD is correct.** `const AAD: &[u8] = b"shadow-vault:v1"` — 15 bytes, ASCII. Used in both `aead_seal()` and `aead_open()` as `Payload { aad: AAD }`. Verified by `aad_value_locked`.

7. **RFC 8439 §2.8.2 test vector passes.** Full AEAD round-trip with official test vector verified in `rfc_8439_test_vector` and `self_test()`.

8. **AEAD tag verification is all-or-nothing.** `chacha20poly1305` crate returns `Err` on tag mismatch — no partial plaintext. Verified by `aead_wrong_key_fails`, `aead_corrupted_ciphertext_fails`, `aead_corrupted_tag_fails`, `aead_truncated_ciphertext_fails`, proptest `single_bit_flip_always_detected`.

9. **Constant-time tag comparison.** The `chacha20poly1305` crate uses the `subtle` crate for constant-time Poly1305 tag comparison.

10. **Rejection sampling is correct.** `uniform_offset()` uses 5 candidates from 20 bytes, rejection at `u32::MAX - (u32::MAX % range)`, little-endian byte parsing. Bias is at most 1/2^32 per candidate. Verified by `uniform_offset_within_range`, `uniform_offset_deterministic`, proptest `offset_always_in_range`.

11. **Slot isolation guaranteed.** `derive_all_keys()` prevents overlapping slots via two-phase collision resolution with cross-phase fallback. If resolution fails, container creation is aborted. Verified by `container_slots_do_not_overlap`, proptest `slot_isolation_guaranteed`.

12. **Message encoding is correct.** 4-byte LE length prefix + message + CSPRNG padding = `slot_size` bytes. Maximum message = `slot_size - 4`. Verified by `encode_decode_round_trip`, `encode_max_length_message`, `encode_rejects_oversized_message`, `container_max_message_length`.

13. **Zeroization on all paths.** `DerivedKeyMaterial` and `ResolvedKeys` implement `Drop` with `.zeroize()`. Salts, Argon2id output, plaintext slots, container bytes, and collision resolution intermediates are explicitly zeroed. Verified by code audit.

14. **Worker clears sensitive args after operations.** `clearArgs()` overwrites passphrase/message strings and fills container Uint8Array with zeros. Called on success and error paths.

15. **Failure indistinguishability at UI level.** All error paths in decrypt show "No message found for this passphrase." — no `console.error()` leak. Verified in `decrypt.ts` catch block.

16. **CSP is restrictive.** `default-src 'none'`; `script-src 'self' 'wasm-unsafe-eval'`; `worker-src 'self'`; `form-action 'none'`; `frame-ancestors 'none'`. No `eval()`, no dynamic script loading, no external scripts.

17. **No localStorage/sessionStorage usage.** Verified by grep across all source files.

18. **Input clearing after use.** Encrypt panel clears passphrases and messages after container creation. Decrypt panel clears passphrase after attempt. Auto-clear: 2-minute timer for decrypted message, 5-minute idle timer for all inputs on tab hide.

19. **SharedArrayBuffer is not used.** Container data is transferred, not shared.

20. **Parallelism in WASM produces correct output.** The `argon2` crate computes lanes sequentially without `rayon`, producing identical output for any parallelism value regardless of WASM vs. native execution.

---

## Unverifiable Claims

The following claims cannot be verified from code alone and require runtime testing, formal proof, or external audit:

1. **`zeroize` volatile writes in WASM.** The `zeroize` crate uses `core::ptr::write_volatile`. WASM does not have hardware-level volatile semantics — the JIT compiler could theoretically optimize away the writes. In practice, Rust's compiler respects volatile for `zeroize`, but formal verification of WASM-compiled volatile behavior does not exist. Listed in SECURITY.md §8.

2. **CSPRNG quality from `getrandom` → `crypto.getRandomValues`.** The browser's CSPRNG quality depends on the platform, OS, and browser implementation. `getrandom` with `wasm_js` feature delegates to `crypto.getRandomValues`, which is specified by W3C but not formally verified per-browser.

3. **No residual key material in WASM linear memory.** After `zeroize` writes, the memory positions SHOULD contain zeros, but WASM linear memory is accessible from JavaScript (`WebAssembly.Memory.buffer`) and could be inspected between the computation and zeroing. The window is small but nonzero. Runtime testing with a heap inspector would be needed to verify.

4. **Argon2id output consistency across Rust versions.** The pinned test vectors verify output for the current `argon2` crate version, but future crate updates could change internal behavior. The `Cargo.lock` pins exact versions, but this claim must be re-verified on every dependency update.

---

## Post-Fix Status

- **CRITICAL findings:** 0 found, 0 unresolved.
- **HIGH findings:** 1 found, 1 fixed and committed (`0572c4c`).
- **MEDIUM findings:** 2 found, 2 fixed and committed (`fe3ed4c`, `fcd4c35`).
- **LOW findings:** 3 found, 3 fixed and committed (`f2d95f4`, `d17c70a`, `0990ddd`).
- **INFO observations:** 5 documented.
- **Known limitations:** 5 added to SECURITY.md §8.
- **Test suite:** 79 tests pass (77 baseline + 2 new validation tests).
- **TypeScript:** Compiles cleanly (`tsc --noEmit`).
- **SPEC.md:** Updated §7 and §8.3 to reflect constant-time decryption.
- **THREAT_MODEL.md:** Updated §2.3, §2.6, §2.7 with detailed attack descriptions.
- **SECURITY.md:** Added §8 Known Limitations.
