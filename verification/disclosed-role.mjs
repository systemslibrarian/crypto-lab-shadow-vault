// Optional independent check: requires Node >=24.7 with node:crypto Argon2.
// Uses the shipped WASM only to create the container; classification uses
// Node's independent Argon2id and ChaCha20-Poly1305 implementations.
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { create_container, initSync, self_test } from '../public/shadow_vault_crypto.js';
assert.equal(typeof crypto.argon2Sync, 'function', 'This check requires Node >=24.7; not run is not a pass');
initSync({module: readFileSync(new URL('../public/shadow_vault_crypto_bg.wasm', import.meta.url))});
assert.equal(self_test().passed, true);
const created = create_container('secret message', 'decoy message', 'strong-real-demo', 'weak-decoy-demo', 4096, 16384, 2, 1);
const container = Buffer.from(created.container);
assert.equal(container.length, 4096);
// Only container bytes and the one supplied password enter this function.
function classify(bytes, password) {
  const matches = [], size = Math.floor(bytes.length / 3), range = bytes.length - size - 16;
  for (const role of ['real', 'decoy']) for (let counter = 0; counter < 8; counter++) {
    const salt = crypto.createHash('sha256').update(`shadow-vault:v1:${role}${counter ? ':c' + counter : ''}`).digest();
    const material = crypto.argon2Sync('argon2id', { message: password, nonce: salt, parallelism: 1, tagLength: 64, memory: 16384, passes: 2 });
    const limit = 0xffffffff - (0xffffffff % range);
    const seeds = Array.from({ length: 5 }, (_, i) => material.readUInt32LE(44 + 4 * i));
    const offset = (seeds.find(seed => seed < limit) ?? seeds[0]) % range;
    const sealed = bytes.subarray(offset, offset + size + 16);
    let plaintext;
    try {
      const cipher = crypto.createDecipheriv('chacha20-poly1305', material.subarray(0, 32), material.subarray(32, 44), { authTagLength: 16 });
      cipher.setAAD(Buffer.from('shadow-vault:v1'));
      cipher.setAuthTag(sealed.subarray(size));
      plaintext = Buffer.concat([cipher.update(sealed.subarray(0, size)), cipher.final()]);
    } catch { continue; }
    const length = plaintext.readUInt32LE();
    assert.ok(length <= size - 4);
    matches.push({ role, counter, offset, message: plaintext.subarray(4, 4 + length).toString('utf8') });
  }
  return matches;
}
const disclosed = classify(container, 'weak-decoy-demo');
assert.equal(disclosed.length, 1);
assert.equal(disclosed[0].role, 'decoy');
assert.equal(disclosed[0].message, 'decoy message');
assert.ok(!disclosed.some(match => match.message === 'secret message'));
// A bounded guess list recovers only the decoy. This is a counterexample to
// automatic recovery of both messages, not proof of real-password entropy.
const dictionary = ['wrong-guess-one', 'wrong-guess-two', 'weak-decoy-demo'];
const dictionaryMatches = dictionary.flatMap(password => classify(container, password));
assert.equal(dictionaryMatches.length, 1);
assert.equal(dictionaryMatches[0].role, 'decoy');
assert.equal(dictionaryMatches[0].message, 'decoy message');
assert.ok(!dictionaryMatches.some(match => match.message === 'secret message'));
const realControl = classify(container, 'strong-real-demo');
assert.equal(realControl.length, 1);
assert.equal(realControl[0].role, 'real');
assert.equal(realControl[0].message, 'secret message');
assert.deepEqual(classify(container, 'unrelated-wrong-password'), []);
console.log(JSON.stringify({ wasmSha256: crypto.createHash('sha256').update(readFileSync(new URL('../public/shadow_vault_crypto_bg.wasm', import.meta.url))).digest('hex'), containerSha256: crypto.createHash('sha256').update(container).digest('hex'), parameters: { memoryKiB: 16384, iterations: 2, lanes: 1 }, disclosed, dictionaryCandidateCount: dictionary.length, dictionaryMatches, realControl, wrongPasswordMatches: 0, attackInputs: 'container plus disclosed password; real-password control is separate' }, null, 2));
