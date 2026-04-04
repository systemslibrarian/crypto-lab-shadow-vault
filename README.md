# Shadow Vault

**Deniable encryption — two messages, one container, no trace.**

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
| Key derivation | Argon2id (WASM via argon2-browser) | [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106) |
| Symmetric encryption | ChaCha20-Poly1305 AEAD | [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) |
| Random generation | Web Crypto API (`crypto.getRandomValues`) | [W3C Web Crypto](https://www.w3.org/TR/WebCryptoAPI/) |
| Salt derivation | SHA-256 (deterministic from role) | [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) |

**Argon2id parameters (default):**
- Memory: 64 MB (65536 KiB) — RFC 9106 minimum for interactive use
- Iterations: 3 — RFC 9106 recommended
- Parallelism: 4
- Output: 64 bytes (key + nonce + offset seed)

**ChaCha20-Poly1305:** Implemented in pure TypeScript per RFC 8439. Verified against all RFC test vectors on every app load (§2.3.2, §2.4.2, §2.5.2, §2.8.2). WebCrypto does not expose ChaCha20-Poly1305 — AES-GCM is not a substitute for this use case.

## What This Cannot Protect Against

- **Implementation bugs** in this demonstration code
- **Keyloggers** or compromised devices capturing passphrases
- **Coercion with violence** (rubber-hose cryptanalysis)
- **Metadata** outside the container — filenames, timestamps, access logs, browser history
- **Browser memory** not being securely wiped (JavaScript has no `memset_s`)
- **Traffic analysis** if the container is transmitted over a network

## Honest Limitations

Shadow Vault is a **demonstration of deniable encryption concepts**, not production-grade deniable storage. The ChaCha20-Poly1305 implementation is RFC-verified but has not undergone a formal security audit. Browser-based cryptography inherits all the limitations of the browser security model.

For real-world deniable encryption, use [VeraCrypt](https://veracrypt.fr) with hidden volumes.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Build | Vite + TypeScript (strict mode) |
| Styling | Tailwind CSS |
| Key derivation | argon2-browser (Argon2id WASM) |
| Symmetric crypto | ChaCha20-Poly1305 (pure TypeScript, RFC 8439) |
| Deployment | GitHub Pages via Actions |
| Persistence | None — zero backend, zero storage |

## Local Setup

```bash
git clone https://github.com/systemslibrarian/shadow-vault.git
cd shadow-vault
npm install
npm run dev
```

Build for production:
```bash
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

## Data Sources

- [RFC 9106 — Argon2 Memory-Hard Function](https://datatracker.ietf.org/doc/html/rfc9106)
- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
- [VeraCrypt Documentation — Hidden Volumes](https://veracrypt.fr/en/Hidden%20Volume.html)
- [NIST SP 800-132 — Recommendation for Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)

---

*So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
