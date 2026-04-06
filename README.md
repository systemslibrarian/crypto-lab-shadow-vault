# Shadow Vault

**Deniable encryption — two messages, one container, no trace.**

**[Live Demo](https://systemslibrarian.github.io/crypto-lab-shadow-vault/)**

You are detained. They demand your passphrase. You comply. They decrypt a plausible message — a grocery list, a journal entry, a note to a friend. What they cannot prove, cannot detect, and cannot even test for: a second encrypted message hidden at a different offset in the same container, decryptable only with a different passphrase they don't know exists.

Shadow Vault is a browser-based demonstration of deniable encryption using a fixed-size container that holds two independently encrypted messages. The real passphrase decrypts the real message. The decoy passphrase decrypts the decoy. The container is structurally indistinguishable from random bytes — there are no headers, no magic bytes, no length fields, no forensic fingerprint.

## How It Works

```
Passphrase A → Argon2id (64 bytes) → key[0..31] + nonce[32..43] + offset[44..47]
                                        ↓                            ↓
                              ChaCha20-Poly1305 encrypt    position in container

Passphrase B → Argon2id (64 bytes) → key[0..31] + nonce[32..43] + offset[44..47]
                                        ↓                            ↓
                              ChaCha20-Poly1305 encrypt    position in container

Container = CSPRNG random bytes (fixed size: 4KB–32KB)
          + real ciphertext at offset A
          + decoy ciphertext at offset B
          + everything else remains random padding
```

1. A fixed-size container is filled entirely with cryptographically random bytes
2. Each passphrase independently derives an encryption key, nonce, and slot offset via Argon2id
3. Each message is encrypted with ChaCha20-Poly1305 and written at its derived offset
4. The result looks like random data — indistinguishable from the CSPRNG padding

## Why Argon2id Is Load-Bearing

Argon2id is not incidental here — it is the security foundation of the deniability model.

Without memory-hard key derivation, an attacker who gains the container could brute-force both passphrases simultaneously, recovering both offsets and both messages. Argon2id with high memory parameters (64MB+ per derivation, per RFC 9106) makes this computationally hopeless. The cost scales per passphrase attempt — attacking two independent passphrases costs twice as much.

The UI makes this explicit: tune the Argon2id parameters down and watch the derivation time drop to dangerous levels.

## The Crypto Stack

| Component | Implementation | Reference |
|-----------|---------------|-----------|
| Key derivation | Argon2id (Rust → WASM, `argon2` crate) | [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106) |
| Symmetric encryption | ChaCha20-Poly1305 AEAD (Rust → WASM, `chacha20poly1305` crate) | [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) |
| Memory zeroing | Guaranteed via `zeroize` crate (compiler barriers) | [zeroize](https://docs.rs/zeroize) |
| Random generation | `getrandom` crate (backed by Web Crypto API in WASM) | [W3C Web Crypto](https://www.w3.org/TR/WebCryptoAPI/) |
| Salt derivation | SHA-256 (deterministic from role, `sha2` crate) | [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) |

**All cryptographic operations run in a Web Worker** — key material never leaves WASM linear memory. The RustCrypto crates (`argon2`, `chacha20poly1305`) are community-audited implementations. The `zeroize` crate uses `volatile` writes to guarantee sensitive memory is zeroed before deallocation, which JavaScript's `fill(0)` cannot guarantee.

**Argon2id parameters (default):**
- Memory: 64 MB (65536 KiB) — RFC 9106 minimum for interactive use
- Iterations: 3 — RFC 9106 recommended
- Parallelism: 4
- Output: 64 bytes (key + nonce + offset seed)

**ChaCha20-Poly1305:** Implemented in Rust via the `chacha20poly1305` crate (RustCrypto). Verified against RFC 8439 test vectors on every app load. All crypto runs in a Web Worker via WASM — the main thread never handles key material.

## What This Cannot Protect Against

- **Implementation bugs** in this demonstration code
- **Keyloggers** or compromised devices capturing passphrases
- **Coercion with violence** (rubber-hose cryptanalysis)
- **Metadata** outside the container — filenames, timestamps, access logs, browser history
- **Browser memory** — passphrases enter as JavaScript strings (immutable, GC'd) before crossing to WASM. Rust/WASM zeroes all key material deterministically, but passphrase strings in JS are unavoidable.
- **Traffic analysis** if the container is transmitted over a network

## Honest Limitations

Shadow Vault uses **audited RustCrypto crates** compiled to WASM, but the integration and container format have not undergone a formal security audit. Browser-based cryptography inherits all the limitations of the browser security model (extensions, devtools, OS-level attacks).

Passphrases still enter via HTML `<input>` elements as immutable JavaScript strings — Rust/WASM cannot zero those. Everything else (keys, nonces, salts, plaintext slots) is zeroed deterministically via the `zeroize` crate.

**Strong, unique passphrases are required for both real and decoy messages.** Deniability depends on the attacker being unable to brute-force either passphrase. Weak passphrases collapse the entire security model regardless of Argon2id parameters.

Decrypted messages are auto-cleared after 2 minutes. Sensitive inputs are cleared on idle and on page unload.

This tool is weaker than a native application under serious threat models. For real-world deniable encryption, use [VeraCrypt](https://veracrypt.fr) with hidden volumes.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Crypto core | Rust → WASM (`argon2`, `chacha20poly1305`, `zeroize` crates) |
| Build (WASM) | `wasm-pack` + `wasm-bindgen` |
| Build (frontend) | Vite + TypeScript (strict mode) |
| Styling | Tailwind CSS |
| Deployment | GitHub Pages via Actions |
| Persistence | None — zero backend, zero storage |

## Local Setup

**Prerequisites:** Rust toolchain + `wasm-pack`

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

```bash
git clone https://github.com/systemslibrarian/crypto-lab-shadow-vault.git
cd crypto-lab-shadow-vault
npm install
npm run wasm     # Build Rust crypto → WASM
npm run dev      # Start dev server
```

Build for production:
```bash
npm run wasm     # Must run before build
npm run build    # outputs to out/
```

Type-check:
```bash
npm run typecheck
```

## Related Projects

| Project | Description |
|---------|------------|
| [phantom-vault](https://systemslibrarian.github.io/phantom-vault/) | Argon2id + HMAC-DRBG stateless password generation |
| [corrupted-oracle](https://systemslibrarian.github.io/corrupted-oracle/) | ChaCha20-DRBG + Dual_EC backdoor demonstration |

## Documentation

| Document | Description |
|----------|-------------|
| [SPEC.md](SPEC.md) | Container format specification — derivation rules, slot layout, collision resolution, pinned test vectors |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Security boundaries, trust model, deniability constraints, honest limitations |
| [SECURITY.md](SECURITY.md) | Security review checklist for auditors — zeroization, format integrity, failure indistinguishability |

## Data Sources

- [RFC 9106 — Argon2 Memory-Hard Function](https://datatracker.ietf.org/doc/html/rfc9106)
- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
- [VeraCrypt Documentation — Hidden Volumes](https://veracrypt.fr/en/Hidden%20Volume.html)
- [NIST SP 800-132 — Recommendation for Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)

---

*So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
