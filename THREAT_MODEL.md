# Shadow Vault — Threat Model

This document defines the security boundaries, threat categories, and honest limitations of Shadow Vault as a browser-based deniable encryption tool.

---

## 1. What Shadow Vault Defends Against

### 1.1 Passive file analysis

An adversary who obtains the container file sees a fixed-size block of bytes with no headers, magic bytes, length fields, or structural markers. Statistical analysis (chi-squared, entropy per byte) shows uniform distribution — indistinguishable from `/dev/urandom` output, a LUKS header pad, or any other random blob.

**Tested:** `container_is_full_size`, `independent_containers_differ`, `all_zeros_container_no_match`, `all_ones_container_no_match`.

### 1.2 Single-passphrase coercion

An adversary who compels the user to reveal one passphrase decrypts one message. The remaining bytes — including the other encrypted slot — are indistinguishable from the CSPRNG padding that fills the rest of the container. There is no way to prove a second message exists without the second passphrase.

**Constraint:** This only works if the revealed passphrase is the decoy. If the adversary already knows both passphrases, deniability is void.

### 1.3 Offline brute-force (weak passphrases)

Argon2id with high memory parameters (default: 64 MB, 3 iterations, parallelism 4) makes per-guess cost significant. With a strong passphrase (80+ bits of entropy), brute-force is computationally infeasible.

**Constraint:** Deniability collapses if *either* passphrase can be brute-forced. Both passphrases must be strong.

### 1.4 Ciphertext integrity

ChaCha20-Poly1305 AEAD with a fixed AAD (`shadow-vault:v1`) provides both confidentiality and integrity. Any modification to the ciphertext, tag, or associated data causes decryption to fail.

**Tested:** `single_bit_flip_detected`, `tag_bit_flip_detected`, `truncated_container_rejected`.

### 1.5 Format oracle attacks

Wrong passphrases, corrupted containers, truncated files, and all other failure modes produce the same generic response: `{success: false}`. No error messages, timing differences, or side channels distinguish "wrong passphrase" from "corrupted data."

**Tested:** All error paths in `open_container` return the same `{success: false}` object.

---

## 2. What Shadow Vault Does NOT Defend Against

### 2.1 Compromised runtime environment

Shadow Vault runs in a browser. If the browser, OS, or hardware is compromised, all bets are off:

- **Keyloggers** capture passphrases before they reach the application
- **Browser extensions** can read DOM inputs, intercept Worker messages, or exfiltrate data
- **Compromised WASM** — if the served `.wasm` file is modified, all security guarantees are void
- **DevTools / memory dumps** — an adversary with local access can inspect JS heap, Worker state, and WASM linear memory

### 2.2 JavaScript string immutability

Passphrases enter the system as JavaScript strings, which are:

- **Immutable and GC-managed** — they cannot be securely zeroed
- **Potentially interned** — the engine may keep copies in string pools
- **Visible in heap snapshots** — a motivated attacker with DevTools access can find them

**Mitigation (partial):** Input values are cleared (`input.value = ''`) after use, and the crypto Worker uses `postMessage` to limit scope. But this is defense-in-depth, not a guarantee.

### 2.3 Side-channel attacks

- **Timing:** Argon2id timing is deterministic for given parameters, but JavaScript/WASM execution timing varies by browser, load, and GC pressure. No constant-time guarantees exist for the JS bridge.
- **Power/EM:** Not applicable to a browser threat model.
- **Cache timing:** WASM execution may leak information through cache timing, but exploiting this requires local access (which already breaks the model — see §2.1).

### 2.4 Metadata outside the container

The container itself has no metadata, but the surrounding context does:

- **Filenames** (`vault_1234567890.bin`) reveal the tool was used
- **Browser history** may show the Shadow Vault URL
- **Filesystem timestamps** reveal when the file was created/modified/accessed
- **Download logs** in the browser record file creation
- **Network logs** — if the page was loaded over HTTPS, the request is logged

**Mitigation:** Users should rename files, clear browser history, and be aware of filesystem metadata. Shadow Vault cannot control anything outside its container.

### 2.5 Rubber-hose cryptanalysis

Physical coercion cannot be solved with cryptography. If an adversary uses violence, deniable encryption provides limited protection — the adversary can demand *all* passphrases and threaten consequences for noncompliance.

Deniability helps only if the adversary *believes* the decoy passphrase is the only passphrase.

### 2.6 Multi-snapshot analysis

If an adversary obtains multiple container snapshots (e.g., cloud backups) encrypted with the same passphrases but different messages, they can diff the containers and identify which byte ranges change. This breaks deniability by revealing that two independent slots exist.

**Mitigation:** Never reuse the same passphrases for different messages. Each container should use fresh, unique passphrases.

### 2.7 Supply-chain attacks

Shadow Vault is served as static files from GitHub Pages. If the repository, CI pipeline, or CDN is compromised, the served code could be modified to exfiltrate passphrases.

**Mitigation:** Subresource integrity is not used (the WASM module is self-hosted). Users who require high assurance should audit the source, build locally, and serve from a trusted origin.

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────┐
│  BROWSER (untrusted environment)            │
│  ┌───────────────────────────────────────┐  │
│  │  Main Thread (UI)                     │  │
│  │  - Reads passphrases from DOM inputs  │  │
│  │  - Sends strings via postMessage      │  │
│  │  - Receives container bytes           │  │
│  │  - Clears inputs after use            │  │
│  └──────────────┬────────────────────────┘  │
│                 │ postMessage                │
│  ┌──────────────▼────────────────────────┐  │
│  │  Web Worker                           │  │
│  │  - Loads WASM module                  │  │
│  │  - Passes args to WASM functions      │  │
│  │  - Returns results via postMessage    │  │
│  └──────────────┬────────────────────────┘  │
│                 │ wasm-bindgen FFI           │
│  ┌──────────────▼────────────────────────┐  │
│  │  WASM Linear Memory (Rust)            │  │
│  │  - All key derivation (Argon2id)      │  │
│  │  - All encryption (ChaCha20-Poly1305) │  │
│  │  - Slot encoding/decoding             │  │
│  │  - Zeroization via zeroize crate      │  │
│  │  - Container construction             │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### What crosses the boundary

| Direction | Data | Risk |
|-----------|------|------|
| UI → Worker | Passphrases (strings) | JS string immutability (§2.2) |
| UI → Worker | Messages (strings) | Same |
| UI → Worker | Container bytes (Uint8Array) | Transferred, not copied |
| Worker → UI | Result object (container bytes, offsets) | Container bytes transferred |
| Worker → WASM | Same as UI → Worker | wasm-bindgen copies into linear memory |
| WASM → Worker | Result object | wasm-bindgen copies out of linear memory |

### What stays inside WASM

- Derived keys, nonces, salts (zeroed on drop)
- Intermediate Argon2id state
- Plaintext slot buffers (zeroed before return)
- CSPRNG random fill operations

---

## 4. Deniability Boundaries

### What deniability provides

- The ability to reveal a *plausible* message while keeping the *real* message hidden
- A container that is forensically indistinguishable from random data
- No structural evidence that a second message exists

### What deniability requires

- **Both passphrases must be strong** — if either can be brute-forced, the adversary finds both messages
- **The decoy message must be plausible** — a nonsensical decoy is suspicious
- **The user must not reveal both passphrases** — once both are known, deniability is void
- **The container must not be diffed against other versions** — see §2.6

### What deniability does NOT provide

- Protection against a sophisticated adversary who already suspects dual messages
- Proof of innocence — only plausible deniability
- Protection if the adversary has access to the device (keyloggers, screen capture, etc.)

---

## 5. Dependency Trust

| Crate | Version | Purpose | Trust basis |
|-------|---------|---------|-------------|
| `argon2` | 0.5 | Key derivation | RustCrypto, widely audited |
| `chacha20poly1305` | 0.10 | AEAD encryption | RustCrypto, RFC 8439 compliance tested |
| `zeroize` | 1 | Memory zeroing | RustCrypto, `#[derive(Zeroize)]` |
| `sha2` | 0.10 | Salt derivation | RustCrypto |
| `getrandom` | 0.3 | CSPRNG (via `crypto.getRandomValues`) | Standard, browser-native backend |
| `wasm-bindgen` | 0.2 | JS ↔ WASM bridge | Mozilla-maintained |
| `js-sys` | 0.3 | JS object construction | Mozilla-maintained |

All cryptographic operations use the RustCrypto ecosystem. No custom cryptographic primitives are implemented.
