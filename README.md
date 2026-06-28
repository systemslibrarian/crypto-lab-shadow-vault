# crypto-lab-shadow-vault

## What It Is

Shadow Vault is a browser demonstration of deniable encryption that combines Argon2id key derivation, ChaCha20-Poly1305 AEAD encryption, and SHA-256 salt derivation in a fixed-size random container. It solves the problem of plausibly revealing one decryptable message while keeping a second message hidden in the same blob without headers or structural markers. The cryptographic core is symmetric encryption with password-based key derivation, executed in Rust/WASM through a Web Worker. It is not asymmetric, threshold, or zero-knowledge cryptography, and it is not positioned as production deniable storage.

## When to Use It

- Use it to teach deniable-encryption mechanics, because the UI exposes Argon2id memory/iteration/parallelism and shows how slot offsets are derived from passphrases.
- Use it for controlled demos of coercion scenarios, because one passphrase decrypts a plausible decoy while another decrypts the real payload.
- Use it to experiment with passphrase-cost tuning, because Argon2id settings directly change derivation cost and brute-force resistance.
- Do not use it for high-assurance operational secrecy, because browser runtime risks and JavaScript passphrase handling are explicitly called out in the threat model — it is a teaching demo, not production deniable storage.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/)**

The demo lets you encrypt and decrypt containers end-to-end in the browser. In encrypt mode, you enter real and decoy passphrases/messages, choose container size (4/8/16/32 KB), and tune Argon2id parameters (memory, iterations, parallelism). In decrypt mode, you upload a vault file and try a passphrase to open whichever message that passphrase maps to.

## What Can Go Wrong

- Passphrase reuse across multiple containers can break deniability, because deterministic key/nonce/offset derivation enables cross-container analysis and two-time-pad style leakage.
- Weak real or decoy passphrases collapse the model, because brute-forcing either passphrase can expose both slot locations and messages.
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

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
