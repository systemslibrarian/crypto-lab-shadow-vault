# crypto-lab-shadow-vault

## What It Is

Shadow Vault is a browser demonstration of deniable encryption that combines Argon2id key derivation, ChaCha20-Poly1305 AEAD encryption, and SHA-256 domain separation in a fixed-size random container. It demonstrates two independently encrypted slots in the same blob. A format-aware reader knows two slots are written and can classify a disclosed passphrase as the configured real or decoy role by authenticating the public role/counter candidates. This requires no knowledge of the other passphrase, but does not recover the unopened plaintext or establish the meaning or importance of either message. It provides no role privacy; hiding labels in the UI does not change this. The cryptographic core is symmetric encryption with password-based key derivation, executed in Rust/WASM through a Web Worker. It is not asymmetric, threshold, or zero-knowledge cryptography, and it is not positioned as production deniable storage.

## When to Use It

- Use it to teach deniable-encryption mechanics, because the UI exposes Argon2id memory/iteration/parallelism and shows how slot offsets are derived from passphrases.
- Use it for controlled demos of coercion scenarios, because one passphrase decrypts a plausible decoy while another decrypts the real payload.
- Use it to experiment with passphrase-cost tuning, because Argon2id settings directly change derivation cost and brute-force resistance.
- Do not use it for high-assurance operational secrecy, because browser runtime risks and JavaScript passphrase handling are explicitly called out in the threat model — it is a teaching demo, not production deniable storage.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/)**

The demo lets you encrypt and decrypt containers end-to-end in the browser. In encrypt mode, you enter real and decoy passphrases/messages, choose container size (4/8/16/32 KB), and tune Argon2id parameters (memory, iterations, parallelism). In decrypt mode, you upload a vault file, select the Argon2id settings used at creation (the headerless file cannot store them), and try a passphrase to open whichever message that passphrase maps to.

Several exhibits demonstrate the mechanics and their limits:

1. **Animated container lifecycle** — on encrypt, the container map paints all 512 cells as flickering random noise, animates the real and decoy slots writing in at their passphrase-derived offsets, then dissolves the slot colours back into noise-grey. A **"What an attacker sees"** toggle removes the legend so the map becomes uniform random cells, letting you compare the insider view against the adversary's view of the same bytes.
2. **Coercion-scenario walkthrough** — after creating a vault, one click re-decrypts the same container with the decoy passphrase (the plausible message an adversary can force out) and then the real passphrase, side by side, through the real Rust/WASM open path — showing that the disclosed password authenticates its decoy role while the second opening uses a separately supplied real password. It does not establish deniability against a format-aware adversary.
3. **Measured Argon2id cost** — the parameter panel runs a real derivation on this device and reports the measured wall-clock time (no hard-coded estimate), paired with a live attacker-cost readout showing how brute-forcing a 40-bit vs 60-bit passphrase scales as you raise the memory cost.
4. **Deliberate redaction** — the decrypt view shows the recovered slot offset as a filled bar with the number withheld, and returns an identical failure message for wrong passphrases and errors alike, as a presentation choice. The bar intentionally reveals approximate position, and an offline reader can authenticate a disclosed password's configured role regardless of UI redaction.

## What Can Go Wrong

- Passphrase reuse across multiple containers can break deniability, because deterministic key/nonce/offset derivation enables cross-container analysis and two-time-pad style leakage.
- Guessing a passphrase exposes its own message, configured role and offset. It does not automatically yield the other independently chosen passphrase, key or plaintext. Knowing one slot and the nonoverlap rule can restrict possible positions for the other slot without decrypting it. Correlated passwords can make the second password easier to guess; reuse across containers adds the separate deterministic-key/nonce risks documented in the threat model.
- JavaScript string handling is an implementation pitfall, because passphrases enter the app as immutable JS strings that cannot be securely zeroized like WASM buffers.
- Unicode normalization mismatches can lock users out, because visually identical passphrases may encode to different UTF-8 byte sequences on different platforms.
- A non-plausible decoy undermines coercion resistance, because deniable encryption relies on the revealed message being believable to an adversary.

## Real-World Usage

- TLS (including TLS 1.3 and TLS 1.2 ChaCha20-Poly1305 suites) uses ChaCha20-Poly1305 as an authenticated encryption option for transport security.
- QUIC/HTTP-3 deployments commonly rely on TLS 1.3 cipher suites that include ChaCha20-Poly1305, especially on devices without AES acceleration.
- WireGuard uses ChaCha20-Poly1305 for packet encryption and authentication in its Noise-based protocol design.
- OpenSSH supports chacha20-poly1305@openssh.com to provide authenticated stream encryption for SSH sessions.
- libsodium exposes Argon2id via crypto_pwhash for password hashing and key derivation in real applications.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-shadow-vault
cd crypto-lab-shadow-vault
npm install
npm run dev
```

## Independent Role-Disclosure Check

With Node >=24.7, run `node verification/disclosed-role.mjs`. The shipped WASM creates a 4096-byte container at 16384 KiB / 2 iterations / 1 lane; Node's independent crypto implementation then receives only the container and one password and tests public role/counter candidates. The decoy-only attack, a bounded three-candidate dictionary recovering only the decoy, a separately supplied real-password control and a wrong-password negative control are asserted. The bounded dictionary is a counterexample to automatic two-message recovery, not an entropy or exhaustive password-search claim. Unsupported Node versions fail explicitly rather than pretending the check passed. This is artifact behavior evidence, not source-to-binary provenance or a timing/security audit. Browser regression coverage exercises the actual coercion flow at desktop, 380px and 320px and keeps the role limit visible.

## Related Demos

- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — the ChaCha20 stream cipher that underlies this demo's ChaCha20-Poly1305 AEAD.
- [crypto-lab-kdf-arena](https://systemslibrarian.github.io/crypto-lab-kdf-arena/) — Argon2id, scrypt, PBKDF2, and HKDF side by side, the password-hashing family used here for key derivation.
- [crypto-lab-phantom-vault](https://systemslibrarian.github.io/crypto-lab-phantom-vault/) — Argon2id + HMAC-DRBG stateless password generation, a sibling vault demo.
- [crypto-lab-corrupted-oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) — ChaCha20-DRBG and the Dual_EC backdoor demonstration.
- [crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/) — authenticated public-key encryption (ECIES, RSA-OAEP, AES-256-GCM).

## Documentation

| Document | Description |
|----------|-------------|
| [SPEC.md](SPEC.md) | Container format specification — derivation rules, slot layout, collision resolution, pinned test vectors |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Security boundaries, trust model, deniability constraints, honest limitations |
| [SECURITY.md](SECURITY.md) | Security review checklist for auditors — zeroization, format integrity, failure indistinguishability |

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
