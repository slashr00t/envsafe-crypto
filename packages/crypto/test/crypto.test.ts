import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateKey,
  exportKey,
  importKey,
  encrypt,
  encryptBytes,
  decrypt,
  decryptBytes,
  keyToFragment,
  buildShareLink,
  keyFromFragment,
  wrapKeyWithPassphrase,
  unwrapKeyWithPassphrase,
  bytesToBase64url,
  base64urlToBytes,
  ENVELOPE_VERSION,
  ALG,
  KEY_BITS,
  IV_BYTES,
  KDF,
  PBKDF2_ITERATIONS,
  SALT_BYTES,
  type Envelope,
} from "../src/index.ts";

// Flip one base64url character to a different but still valid character. This
// keeps the value decodable so the failure under test is the GCM check, not a
// decode error.
function tamperChar(value: string, index: number): string {
  const current = value[index]!;
  const replacement = current === "A" ? "B" : "A";
  return value.slice(0, index) + replacement + value.slice(index + 1);
}

test("encrypt and decrypt round-trip (string)", async () => {
  const key = await generateKey();
  const envelope = await encrypt(key, "hello, envsafe");
  assert.equal(envelope.v, ENVELOPE_VERSION);
  assert.equal(envelope.alg, ALG);
  assert.equal(await decrypt(key, envelope), "hello, envsafe");
});

test("encrypt and decrypt round-trip (bytes)", async () => {
  const key = await generateKey();
  const data = new Uint8Array([0, 1, 2, 42, 200, 250, 255]);
  const envelope = await encryptBytes(key, data);
  assert.deepEqual(await decryptBytes(key, envelope), data);
});

test("envelope carries no key material", async () => {
  const key = await generateKey();
  const envelope = await encrypt(key, "secret");
  assert.deepEqual(Object.keys(envelope).sort(), ["alg", "ct", "iv", "v"]);
});

test("wrong key is rejected", async () => {
  const keyA = await generateKey();
  const keyB = await generateKey();
  const envelope = await encrypt(keyA, "secret");
  await assert.rejects(() => decrypt(keyB, envelope));
});

test("ciphertext tamper is rejected", async () => {
  const key = await generateKey();
  const envelope = await encrypt(key, "secret payload");
  const tampered: Envelope = { ...envelope, ct: tamperChar(envelope.ct, 0) };
  await assert.rejects(() => decrypt(key, tampered));
});

test("iv tamper is rejected (header bound as AAD)", async () => {
  const key = await generateKey();
  const envelope = await encrypt(key, "secret payload");
  const tampered: Envelope = { ...envelope, iv: tamperChar(envelope.iv, 0) };
  await assert.rejects(() => decrypt(key, tampered));
});

test("version downgrade is rejected", async () => {
  const key = await generateKey();
  const envelope = await encrypt(key, "secret");
  const downgraded = { ...envelope, v: 2 } as unknown as Envelope;
  await assert.rejects(() => decrypt(key, downgraded));
});

test("key export and import round-trip", async () => {
  const key = await generateKey();
  const raw = await exportKey(key);
  assert.equal(raw.length, KEY_BITS / 8);
  const imported = await importKey(raw);
  const envelope = await encrypt(key, "via imported key");
  assert.equal(await decrypt(imported, envelope), "via imported key");
});

test("importKey rejects wrong-length material", async () => {
  await assert.rejects(() => importKey(new Uint8Array(0)));
  await assert.rejects(() => importKey(new Uint8Array(16)));
  await assert.rejects(() => importKey(new Uint8Array(31)));
  await assert.rejects(() => importKey(new Uint8Array(33)));
});

test("a fresh iv is used on every call", async () => {
  const key = await generateKey();
  const first = await encrypt(key, "same plaintext");
  const second = await encrypt(key, "same plaintext");
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.ct, second.ct);
  assert.equal(base64urlToBytes(first.iv).length, IV_BYTES);
});

test("share link fragment round-trip", async () => {
  const key = await generateKey();
  const envelope = await encrypt(key, "shared secret");
  const fragment = await keyToFragment(key);
  const link = buildShareLink("https://envsafe.app/s/abc123", fragment);
  assert.ok(link.includes("#"));
  assert.ok(link.endsWith(fragment));
  const recovered = await keyFromFragment(link);
  assert.equal(await decrypt(recovered, envelope), "shared secret");
});

test("buildShareLink replaces an existing fragment", () => {
  const link = buildShareLink("https://envsafe.app/s/abc123#stale", "fresh");
  assert.equal(link, "https://envsafe.app/s/abc123#fresh");
});

test("passphrase wrap and unwrap round-trip", async () => {
  const key = await generateKey();
  const wrapped = await wrapKeyWithPassphrase(key, "correct horse battery staple");
  assert.equal(wrapped.kdf, KDF);
  assert.equal(wrapped.iterations, PBKDF2_ITERATIONS);
  assert.equal(base64urlToBytes(wrapped.salt).length, SALT_BYTES);

  const unwrapped = await unwrapKeyWithPassphrase(wrapped, "correct horse battery staple");
  const envelope = await encrypt(key, "wrapped secret");
  assert.equal(await decrypt(unwrapped, envelope), "wrapped secret");
});

test("wrong passphrase is rejected", async () => {
  const key = await generateKey();
  const wrapped = await wrapKeyWithPassphrase(key, "right passphrase");
  await assert.rejects(() => unwrapKeyWithPassphrase(wrapped, "wrong passphrase"));
});

test("base64url fuzz for lengths 0..129", () => {
  for (let n = 0; n <= 129; n++) {
    const bytes = new Uint8Array(n);
    globalThis.crypto.getRandomValues(bytes);
    const encoded = bytesToBase64url(bytes);
    assert.match(encoded, /^[A-Za-z0-9_-]*$/, `length ${n} is not url-safe`);
    assert.ok(!encoded.includes("="), `length ${n} carries padding`);
    const decoded = base64urlToBytes(encoded);
    assert.deepEqual(decoded, bytes, `round-trip failed at length ${n}`);
  }
});

test("base64urlToBytes rejects an invalid length", () => {
  assert.throws(() => base64urlToBytes("A"));
});

test("base64urlToBytes rejects an invalid character", () => {
  assert.throws(() => base64urlToBytes("****"));
});

test("base64urlToBytes rejects a non-canonical 2-char tail", () => {
  // "AA" is the only canonical encoding of the single byte 0x00. "AB" leaves the
  // four unused low bits of the last sextet set, which bytesToBase64url never
  // produces, so it must be rejected.
  assert.deepEqual(base64urlToBytes("AA"), new Uint8Array([0]));
  assert.throws(() => base64urlToBytes("AB"));
});

test("base64urlToBytes rejects a non-canonical 3-char tail", () => {
  // "AAA" is the only canonical encoding of the two bytes 0x00 0x00. "AAB"
  // leaves the two unused low bits of the last sextet set, so it must be
  // rejected.
  assert.deepEqual(base64urlToBytes("AAA"), new Uint8Array([0, 0]));
  assert.throws(() => base64urlToBytes("AAB"));
});
