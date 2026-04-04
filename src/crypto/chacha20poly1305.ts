/**
 * ChaCha20-Poly1305 AEAD — RFC 8439 implementation in pure TypeScript.
 *
 * WebCrypto does not expose ChaCha20-Poly1305, so we implement it here.
 * All operations follow RFC 8439 exactly. Test vectors from the RFC are
 * verified at app startup (see selfTest).
 *
 * References:
 *   - RFC 8439 §2.1  ChaCha20 block function
 *   - RFC 8439 §2.4  ChaCha20 encryption
 *   - RFC 8439 §2.5  Poly1305 MAC
 *   - RFC 8439 §2.6  Poly1305 key generation
 *   - RFC 8439 §2.8  AEAD construction
 */

// --- ChaCha20 ---

function u32(x: number): number {
  return x >>> 0;
}

function rotl(v: number, n: number): number {
  return u32((v << n) | (v >>> (32 - n)));
}

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = u32(s[a] + s[b]); s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = u32(s[c] + s[d]); s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = u32(s[a] + s[b]); s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = u32(s[c] + s[d]); s[b] = rotl(s[b] ^ s[c], 7);
}

/**
 * RFC 8439 §2.1 — ChaCha20 block function.
 * Produces 64 bytes of keystream from a 32-byte key, 4-byte counter, and 12-byte nonce.
 */
export function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const kv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const nv = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);

  // State initialization: constants, key, counter, nonce
  const state = new Uint32Array(16);
  // "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  // Key (8 words)
  for (let i = 0; i < 8; i++) state[4 + i] = kv.getUint32(i * 4, true);
  // Counter
  state[12] = u32(counter);
  // Nonce (3 words)
  for (let i = 0; i < 3; i++) state[13 + i] = nv.getUint32(i * 4, true);

  // Working state
  const ws = new Uint32Array(state);

  // 20 rounds = 10 double rounds
  for (let i = 0; i < 10; i++) {
    // Column rounds
    quarterRound(ws, 0, 4,  8, 12);
    quarterRound(ws, 1, 5,  9, 13);
    quarterRound(ws, 2, 6, 10, 14);
    quarterRound(ws, 3, 7, 11, 15);
    // Diagonal rounds
    quarterRound(ws, 0, 5, 10, 15);
    quarterRound(ws, 1, 6, 11, 12);
    quarterRound(ws, 2, 7,  8, 13);
    quarterRound(ws, 3, 4,  9, 14);
  }

  // Add initial state
  for (let i = 0; i < 16; i++) ws[i] = u32(ws[i] + state[i]);

  // Serialize to bytes (little-endian)
  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) ov.setUint32(i * 4, ws[i], true);
  return out;
}

/**
 * RFC 8439 §2.4 — ChaCha20 stream cipher.
 * XORs plaintext with ChaCha20 keystream. initialCounter defaults to 1 for
 * encryption (counter 0 is reserved for Poly1305 key generation per §2.6).
 */
export function chacha20Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  initialCounter: number = 1
): Uint8Array {
  const out = new Uint8Array(plaintext.length);
  const blocks = Math.ceil(plaintext.length / 64);

  for (let i = 0; i < blocks; i++) {
    const block = chacha20Block(key, initialCounter + i, nonce);
    const offset = i * 64;
    const len = Math.min(64, plaintext.length - offset);
    for (let j = 0; j < len; j++) {
      out[offset + j] = plaintext[offset + j] ^ block[j];
    }
  }

  return out;
}

// --- Poly1305 ---

/**
 * RFC 8439 §2.5 — Poly1305 MAC.
 *
 * Uses BigInt for the 130-bit prime field arithmetic.
 * p = 2^130 - 5
 *
 * The one-time key is 32 bytes: r (16 bytes, clamped) and s (16 bytes).
 */
export function poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array {
  const p = (1n << 130n) - 5n;

  // r = le_bytes_to_num(key[0..15]) & clamp
  let r = leToNum(key.subarray(0, 16));
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;

  // s = le_bytes_to_num(key[16..31])
  const s = leToNum(key.subarray(16, 32));

  let acc = 0n;
  const fullBlocks = Math.floor(message.length / 16);

  for (let i = 0; i <= fullBlocks; i++) {
    const start = i * 16;
    const end = Math.min(start + 16, message.length);
    if (start >= message.length) break;

    const blockLen = end - start;
    // n = le_bytes_to_num(block) with hibit
    const block = new Uint8Array(17);
    block.set(message.subarray(start, end));
    block[blockLen] = 1; // hibit
    const n = leToNum(block.subarray(0, blockLen + 1));

    acc = ((acc + n) * r) % p;
  }

  acc = (acc + s) & ((1n << 128n) - 1n);

  return numToLe(acc, 16);
}

/** Convert little-endian bytes to BigInt */
function leToNum(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/** Convert BigInt to little-endian bytes of specified length */
function numToLe(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let val = n;
  for (let i = 0; i < len; i++) {
    out[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return out;
}

/**
 * RFC 8439 §2.6 — Poly1305 one-time key generation.
 * Uses ChaCha20 block with counter=0, takes first 32 bytes.
 */
export function poly1305KeyGen(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const block = chacha20Block(key, 0, nonce);
  return block.slice(0, 32);
}

// --- AEAD Construction ---

/** Pad length to 16-byte boundary */
function padTo16(len: number): Uint8Array {
  const rem = len % 16;
  if (rem === 0) return new Uint8Array(0);
  return new Uint8Array(16 - rem);
}

/**
 * Build Poly1305 message per RFC 8439 §2.8:
 * aad || pad(aad) || ciphertext || pad(ct) || len(aad) as 8-byte LE || len(ct) as 8-byte LE
 */
function buildAuthData(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const aadPad = padTo16(aad.length);
  const ctPad = padTo16(ciphertext.length);
  const lens = new Uint8Array(16);
  const lv = new DataView(lens.buffer);
  // 64-bit little-endian lengths
  lv.setUint32(0, aad.length, true);
  lv.setUint32(4, 0, true);
  lv.setUint32(8, ciphertext.length, true);
  lv.setUint32(12, 0, true);

  const total = aad.length + aadPad.length + ciphertext.length + ctPad.length + 16;
  const result = new Uint8Array(total);
  let offset = 0;
  result.set(aad, offset); offset += aad.length;
  result.set(aadPad, offset); offset += aadPad.length;
  result.set(ciphertext, offset); offset += ciphertext.length;
  result.set(ctPad, offset); offset += ctPad.length;
  result.set(lens, offset);
  return result;
}

/**
 * Constant-time comparison — never short-circuit.
 * Prevents timing side-channel attacks on tag verification.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * RFC 8439 §2.8 — ChaCha20-Poly1305 AEAD Seal (encrypt + authenticate).
 *
 * Returns ciphertext || 16-byte Poly1305 tag.
 */
export function chachaPoly1305Seal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  // Generate one-time Poly1305 key (counter=0)
  const otk = poly1305KeyGen(key, nonce);
  // Encrypt (counter starts at 1)
  const ciphertext = chacha20Encrypt(key, nonce, plaintext, 1);
  // Build auth data and compute tag
  const authData = buildAuthData(aad, ciphertext);
  const tag = poly1305Mac(otk, authData);
  // Concatenate ciphertext + tag
  const result = new Uint8Array(ciphertext.length + 16);
  result.set(ciphertext);
  result.set(tag, ciphertext.length);
  return result;
}

/**
 * RFC 8439 §2.8 — ChaCha20-Poly1305 AEAD Open (verify + decrypt).
 *
 * Returns plaintext on success, null on authentication failure.
 * Uses constant-time tag comparison.
 */
export function chachaPoly1305Open(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array
): Uint8Array | null {
  if (sealed.length < 16) return null;

  const ciphertext = sealed.subarray(0, sealed.length - 16);
  const receivedTag = sealed.subarray(sealed.length - 16);

  // Generate one-time Poly1305 key
  const otk = poly1305KeyGen(key, nonce);
  // Compute expected tag
  const authData = buildAuthData(aad, ciphertext);
  const expectedTag = poly1305Mac(otk, authData);

  // Constant-time tag verification
  if (!constantTimeEqual(receivedTag, expectedTag)) {
    return null;
  }

  // Decrypt
  return chacha20Encrypt(key, nonce, ciphertext, 1);
}

// --- Self-test against RFC 8439 test vectors ---

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

interface SelfTestResult {
  passed: boolean;
  failures: string[];
}

/**
 * Run RFC 8439 test vectors. Called once on app load.
 * If any vector fails, the app displays a fatal error.
 */
export function runSelfTest(): SelfTestResult {
  const failures: string[] = [];

  // --- Test 1: ChaCha20 block function (RFC 8439 §2.3.2) ---
  {
    const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const nonce = hexToBytes('000000090000004a00000000');
    const counter = 1;
    const block = chacha20Block(key, counter, nonce);
    const expected = hexToBytes(
      '10f1e7e4d13b5915500fdd1fa32071c4' +
      'c7d1f4c733c068030422aa9ac3d46c4e' +
      'd2826446079faa0914c2d705d98b02a2' +
      'b5129cd1de164eb9cbd083e8a2503c4e'
    );
    if (bytesToHex(block) !== bytesToHex(expected)) {
      failures.push('ChaCha20 block function (§2.3.2)');
    }
  }

  // --- Test 2: ChaCha20 encryption (RFC 8439 §2.4.2) ---
  {
    const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const nonce = hexToBytes('000000000000004a00000000');
    const plaintext = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    );
    const ciphertext = chacha20Encrypt(key, nonce, plaintext, 1);
    const expected = hexToBytes(
      '6e2e359a2568f98041ba0728dd0d6981' +
      'e97e7aec1d4360c20a27afccfd9fae0b' +
      'f91b65c5524733ab8f593dabcd62b357' +
      '1639d624e65152ab8f530c359f0861d8' +
      '07ca0dbf500d6a6156a38e088a22b65e' +
      '52bc514d16ccf806818ce91ab7793736' +
      '5af90bbf74a35be6b40b8eedf2785e42' +
      '874d'
    );
    if (bytesToHex(ciphertext) !== bytesToHex(expected)) {
      failures.push('ChaCha20 encryption (§2.4.2)');
    }
  }

  // --- Test 3: Poly1305 MAC (RFC 8439 §2.5.2) ---
  {
    const key = hexToBytes(
      '85d6be7857556d337f4452fe42d506a8' +
      '0103808afb0db2fd4abff6af4149f51b'
    );
    const msg = new TextEncoder().encode('Cryptographic Forum Research Group');
    const tag = poly1305Mac(key, msg);
    const expected = hexToBytes('a8061dc1305136c6c22b8baf0c0127a9');
    if (bytesToHex(tag) !== bytesToHex(expected)) {
      failures.push('Poly1305 MAC (§2.5.2)');
    }
  }

  // --- Test 4: AEAD (RFC 8439 §2.8.2) ---
  {
    const key = hexToBytes(
      '808182838485868788898a8b8c8d8e8f' +
      '909192939495969798999a9b9c9d9e9f'
    );
    const nonce = hexToBytes('070000004041424344454647');
    const aad = hexToBytes('50515253c0c1c2c3c4c5c6c7');
    const plaintext = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    );
    const sealed = chachaPoly1305Seal(key, nonce, plaintext, aad);
    const expectedCiphertext = hexToBytes(
      'd31a8d34648e60db7b86afbc53ef7ec2' +
      'a4aded51296e08fea9e2b5a736ee62d6' +
      '3dbea45e8ca9671282fafb69da92728b' +
      '1a71de0a9e060b2905d6a5b67ecd3b36' +
      '92ddbd7f2d778b8c9803aee328091b58' +
      'fab324e4fad675945585808b4831d7bc' +
      '3ff4def08e4b7a9de576d26586cec64b' +
      '6116'
    );
    const expectedTag = hexToBytes('1ae10b594f09e26a7e902ecbd0600691');
    const expectedSealed = new Uint8Array(expectedCiphertext.length + expectedTag.length);
    expectedSealed.set(expectedCiphertext);
    expectedSealed.set(expectedTag, expectedCiphertext.length);

    if (bytesToHex(sealed) !== bytesToHex(expectedSealed)) {
      failures.push('AEAD seal (§2.8.2)');
    }

    // Test open
    const opened = chachaPoly1305Open(key, nonce, sealed, aad);
    if (!opened || new TextDecoder().decode(opened) !== new TextDecoder().decode(plaintext)) {
      failures.push('AEAD open (§2.8.2)');
    }

    // Test that wrong key fails
    const wrongKey = new Uint8Array(key);
    wrongKey[0] ^= 1;
    const wrongResult = chachaPoly1305Open(wrongKey, nonce, sealed, aad);
    if (wrongResult !== null) {
      failures.push('AEAD open should fail with wrong key');
    }
  }

  return { passed: failures.length === 0, failures };
}
