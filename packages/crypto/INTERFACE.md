# @envsafe/crypto - frozen interface

This is the locked contract for `@envsafe/crypto`. The public API and the wire
formats below are frozen. A breaking change requires an `ENVELOPE_VERSION` bump
and a migration path that keeps old data decryptable. The test suite in
`test/crypto.test.ts` is the executable form of this document.

## Design

- AES-GCM-256. A fresh 256-bit key per secret. A fresh 96-bit IV per message.
- The envelope is versioned and carries no key material.
- The header `v;alg;iv` is bound as GCM additional authenticated data, so a
  tampered header fails closed.
- Passphrase wrapping is PBKDF2-HMAC-SHA256 at 600000 iterations. The KDF
  parameters are stored in the wrapped key so they can migrate to a stronger KDF
  later.
- Pure WebCrypto via `globalThis.crypto.subtle`. Zero runtime dependencies. Runs
  in browsers and in Node 20 and newer.
- base64url is hand rolled. It is url-safe, has no padding, and uses no `btoa` or
  `Buffer`.

## Constants

| Name                | Value                  |
| ------------------- | ---------------------- |
| `ENVELOPE_VERSION`  | `1`                    |
| `ALG`               | `"A256GCM"`            |
| `KEY_BITS`          | `256`                  |
| `IV_BYTES`          | `12`                   |
| `KDF`               | `"PBKDF2-HMAC-SHA256"` |
| `PBKDF2_ITERATIONS` | `600000`               |
| `SALT_BYTES`        | `16`                   |

## Types

```ts
interface Envelope {
  readonly v: 1;
  readonly alg: "A256GCM";
  readonly iv: string; // base64url, the 96-bit nonce
  readonly ct: string; // base64url, ciphertext with the appended GCM tag
}

interface WrappedKey {
  readonly v: 1;
  readonly kdf: "PBKDF2-HMAC-SHA256";
  readonly iterations: number;
  readonly salt: string; // base64url
  readonly iv: string; // base64url, the wrapping nonce
  readonly ct: string; // base64url, the wrapped raw key with the GCM tag
}
```

## API

All functions that touch a key or ciphertext are async.

### Keys

- `generateKey(): Promise<CryptoKey>`
  A fresh, extractable AES-GCM-256 key.

- `exportKey(key: CryptoKey): Promise<Uint8Array>`
  The raw 32-byte key.

- `importKey(raw: Uint8Array): Promise<CryptoKey>`
  Imports a raw 32-byte key. Throws if the length is not 32, so a 16-byte or
  24-byte value cannot be silently accepted as a shorter AES key.

### Encryption

- `encrypt(key: CryptoKey, text: string): Promise<Envelope>`
  Encrypts a UTF-8 string.

- `encryptBytes(key: CryptoKey, data: Uint8Array): Promise<Envelope>`
  Encrypts raw bytes. Every call draws a fresh IV.

- `decrypt(key: CryptoKey, envelope: Envelope): Promise<string>`
  Decrypts to a UTF-8 string.

- `decryptBytes(key: CryptoKey, envelope: Envelope): Promise<Uint8Array>`
  Decrypts to raw bytes. Rejects an unknown version, an unknown algorithm, a
  wrong key, and any tampered field.

### Share links

- `keyToFragment(key: CryptoKey): Promise<string>`
  The key as a base64url fragment value.

- `buildShareLink(baseUrl: string, fragment: string): string`
  Returns `baseUrl#fragment`. Any existing fragment on `baseUrl` is replaced.

- `keyFromFragment(fragment: string): Promise<CryptoKey>`
  Recovers the key. Accepts a bare fragment value or a full link, in which case
  the text after the last `#` is used.

### Passphrase wrapping

- `wrapKeyWithPassphrase(key: CryptoKey, passphrase: string): Promise<WrappedKey>`
  Derives a wrapping key with PBKDF2-HMAC-SHA256 at `PBKDF2_ITERATIONS` over a
  fresh salt, then wraps the raw key with AES-GCM.

- `unwrapKeyWithPassphrase(wrapped: WrappedKey, passphrase: string): Promise<CryptoKey>`
  Reverses the wrap. Rejects a wrong passphrase, an unknown version and an
  unknown KDF.

### base64url

- `bytesToBase64url(bytes: Uint8Array): string`
  Url-safe base64 with no padding.

- `base64urlToBytes(input: string): Uint8Array`
  The inverse. Throws on an invalid length, an invalid character, or a
  non-canonical input. Decoding is strict and canonical: in a 2-char tail the
  unused low 4 bits of the last sextet must be zero, and in a 3-char tail the
  unused low 2 bits must be zero. This gives each byte sequence exactly one valid
  encoding. Every string produced by `bytesToBase64url` stays valid. Only
  previously tolerated non-canonical inputs are now rejected.

## Failure behavior

- A wrong key, a tampered ciphertext, a tampered IV, or any header change makes
  decryption reject. The header is authenticated, so the change fails closed
  rather than producing wrong plaintext.
- An envelope whose `v` is not `ENVELOPE_VERSION`, or whose `alg` is not `ALG`,
  is rejected before any decryption is attempted.
- `importKey` rejects raw material that is not exactly 32 bytes.
- `base64urlToBytes` rejects an invalid length, an invalid character, and a
  non-canonical tail, so a byte sequence has exactly one valid encoding.

## Test coverage

The suite covers: encrypt and decrypt round-trips for strings and bytes, wrong
key rejection, ciphertext tamper, IV tamper through the AAD binding, version
downgrade rejection, key export and import with wrong-length rejection, a fresh
IV on every call, the share link fragment round-trip, passphrase wrap and unwrap
with wrong passphrase rejection, a base64url fuzz across input lengths 0 to 129,
and rejection of non-canonical base64url tails.
