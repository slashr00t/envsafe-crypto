/**
 * @envsafe/crypto - frozen client-side crypto core.
 *
 * AES-GCM-256 with a fresh 256-bit key per secret and a fresh 96-bit IV per
 * message. The versioned envelope carries no key material. The header
 * (version;alg;iv) is bound as GCM additional authenticated data, so a tampered
 * header fails closed.
 *
 * Pure WebCrypto via globalThis.crypto.subtle. Zero runtime dependencies. Runs
 * in browsers and in Node 20 and newer.
 *
 * This contract is frozen. See INTERFACE.md. Any change to a signature, a
 * constant or a wire format needs an ENVELOPE_VERSION bump and a migration path.
 */

export const ENVELOPE_VERSION = 1 as const;
export const ALG = "A256GCM" as const;
export const KEY_BITS = 256 as const;
export const IV_BYTES = 12 as const;
export const KDF = "PBKDF2-HMAC-SHA256" as const;
export const PBKDF2_ITERATIONS = 600_000 as const;
export const SALT_BYTES = 16 as const;

const KEY_BYTES = KEY_BITS / 8;

/** The on-the-wire ciphertext envelope. Carries no key material. */
export interface Envelope {
  readonly v: typeof ENVELOPE_VERSION;
  readonly alg: typeof ALG;
  /** base64url, the 96-bit GCM nonce. */
  readonly iv: string;
  /** base64url, ciphertext with the appended GCM tag. */
  readonly ct: string;
}

/**
 * A key wrapped under a passphrase. The KDF parameters are stored so they can
 * migrate to a stronger KDF (for example Argon2id) under a future version
 * without breaking existing wrapped keys.
 */
export interface WrappedKey {
  readonly v: typeof ENVELOPE_VERSION;
  readonly kdf: typeof KDF;
  readonly iterations: number;
  /** base64url, the PBKDF2 salt. */
  readonly salt: string;
  /** base64url, the 96-bit GCM nonce used to wrap the key. */
  readonly iv: string;
  /** base64url, the wrapped raw key with the appended GCM tag. */
  readonly ct: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function webcrypto(): Crypto {
  const candidate = globalThis.crypto;
  if (candidate?.subtle === undefined) {
    throw new Error(
      "envsafe-crypto: WebCrypto is unavailable. Expected globalThis.crypto.subtle.",
    );
  }
  return candidate;
}

function randomBytes(length: number): Uint8Array {
  return webcrypto().getRandomValues(new Uint8Array(length));
}

// Recent TypeScript types a bare Uint8Array as Uint8Array<ArrayBufferLike>, while
// the WebCrypto lib types expect an ArrayBuffer-backed view. These bytes are
// always ArrayBuffer-backed at runtime, so this narrows the type at the boundary
// into subtle.
function subtleBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>;
}

/** The bytes bound as GCM additional authenticated data: "version;alg;iv". */
function headerAad(v: number, alg: string, ivBase64url: string): Uint8Array {
  return encoder.encode(`${v};${alg};${ivBase64url}`);
}

export async function generateKey(): Promise<CryptoKey> {
  return webcrypto().subtle.generateKey({ name: "AES-GCM", length: KEY_BITS }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function exportKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await webcrypto().subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

export async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== KEY_BYTES) {
    throw new Error(
      `envsafe-crypto: key must be ${KEY_BYTES} bytes, received ${raw.length}.`,
    );
  }
  return webcrypto().subtle.importKey("raw", subtleBytes(raw), { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function encryptBytes(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Envelope> {
  const iv = randomBytes(IV_BYTES);
  const ivBase64url = bytesToBase64url(iv);
  const aad = headerAad(ENVELOPE_VERSION, ALG, ivBase64url);
  const ciphertext = await webcrypto().subtle.encrypt(
    { name: "AES-GCM", iv: subtleBytes(iv), additionalData: subtleBytes(aad) },
    key,
    subtleBytes(data),
  );
  return {
    v: ENVELOPE_VERSION,
    alg: ALG,
    iv: ivBase64url,
    ct: bytesToBase64url(new Uint8Array(ciphertext)),
  };
}

export async function encrypt(key: CryptoKey, text: string): Promise<Envelope> {
  return encryptBytes(key, encoder.encode(text));
}

export async function decryptBytes(
  key: CryptoKey,
  envelope: Envelope,
): Promise<Uint8Array> {
  if (envelope.v !== ENVELOPE_VERSION) {
    throw new Error(
      `envsafe-crypto: unsupported envelope version ${String(envelope.v)}.`,
    );
  }
  if (envelope.alg !== ALG) {
    throw new Error(
      `envsafe-crypto: unsupported algorithm ${String(envelope.alg)}.`,
    );
  }
  const iv = base64urlToBytes(envelope.iv);
  const aad = headerAad(envelope.v, envelope.alg, envelope.iv);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await webcrypto().subtle.decrypt(
      { name: "AES-GCM", iv: subtleBytes(iv), additionalData: subtleBytes(aad) },
      key,
      subtleBytes(base64urlToBytes(envelope.ct)),
    );
  } catch {
    throw new Error(
      "envsafe-crypto: decryption failed. Wrong key or tampered envelope.",
    );
  }
  return new Uint8Array(plaintext);
}

export async function decrypt(key: CryptoKey, envelope: Envelope): Promise<string> {
  return decoder.decode(await decryptBytes(key, envelope));
}

export async function keyToFragment(key: CryptoKey): Promise<string> {
  return bytesToBase64url(await exportKey(key));
}

export function buildShareLink(baseUrl: string, fragment: string): string {
  const hashIndex = baseUrl.indexOf("#");
  const base = hashIndex === -1 ? baseUrl : baseUrl.slice(0, hashIndex);
  return `${base}#${fragment}`;
}

export async function keyFromFragment(fragment: string): Promise<CryptoKey> {
  const hashIndex = fragment.lastIndexOf("#");
  const value = hashIndex === -1 ? fragment : fragment.slice(hashIndex + 1);
  return importKey(base64urlToBytes(value));
}

async function deriveWrappingKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const base = await webcrypto().subtle.importKey(
    "raw",
    subtleBytes(encoder.encode(passphrase)),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return webcrypto().subtle.deriveKey(
    { name: "PBKDF2", salt: subtleBytes(salt), iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function wrapKeyWithPassphrase(
  key: CryptoKey,
  passphrase: string,
): Promise<WrappedKey> {
  const raw = await exportKey(key);
  const salt = randomBytes(SALT_BYTES);
  const wrappingKey = await deriveWrappingKey(passphrase, salt, PBKDF2_ITERATIONS);
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await webcrypto().subtle.encrypt(
    { name: "AES-GCM", iv: subtleBytes(iv) },
    wrappingKey,
    subtleBytes(raw),
  );
  return {
    v: ENVELOPE_VERSION,
    kdf: KDF,
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64url(salt),
    iv: bytesToBase64url(iv),
    ct: bytesToBase64url(new Uint8Array(ciphertext)),
  };
}

export async function unwrapKeyWithPassphrase(
  wrapped: WrappedKey,
  passphrase: string,
): Promise<CryptoKey> {
  if (wrapped.v !== ENVELOPE_VERSION) {
    throw new Error(
      `envsafe-crypto: unsupported wrapped-key version ${String(wrapped.v)}.`,
    );
  }
  if (wrapped.kdf !== KDF) {
    throw new Error(`envsafe-crypto: unsupported kdf ${String(wrapped.kdf)}.`);
  }
  const salt = base64urlToBytes(wrapped.salt);
  const wrappingKey = await deriveWrappingKey(passphrase, salt, wrapped.iterations);
  const iv = base64urlToBytes(wrapped.iv);
  let raw: ArrayBuffer;
  try {
    raw = await webcrypto().subtle.decrypt(
      { name: "AES-GCM", iv: subtleBytes(iv) },
      wrappingKey,
      subtleBytes(base64urlToBytes(wrapped.ct)),
    );
  } catch {
    throw new Error(
      "envsafe-crypto: unwrap failed. Wrong passphrase or tampered wrapped key.",
    );
  }
  return importKey(new Uint8Array(raw));
}

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const BASE64URL_LOOKUP = ((): Int16Array => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < BASE64URL_ALPHABET.length; i++) {
    table[BASE64URL_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** Url-safe base64 with no padding. Hand rolled, no btoa or Buffer. */
export function bytesToBase64url(bytes: Uint8Array): string {
  const chunks: string[] = [];
  const len = bytes.length;
  let i = 0;
  for (; i + 3 <= len; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1]!;
    const b2 = bytes[i + 2]!;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    chunks.push(
      String.fromCharCode(
        BASE64URL_ALPHABET.charCodeAt((triple >> 18) & 63),
        BASE64URL_ALPHABET.charCodeAt((triple >> 12) & 63),
        BASE64URL_ALPHABET.charCodeAt((triple >> 6) & 63),
        BASE64URL_ALPHABET.charCodeAt(triple & 63),
      ),
    );
  }
  const remaining = len - i;
  if (remaining === 1) {
    const b0 = bytes[i]!;
    const triple = b0 << 16;
    chunks.push(
      String.fromCharCode(
        BASE64URL_ALPHABET.charCodeAt((triple >> 18) & 63),
        BASE64URL_ALPHABET.charCodeAt((triple >> 12) & 63),
      ),
    );
  } else if (remaining === 2) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1]!;
    const triple = (b0 << 16) | (b1 << 8);
    chunks.push(
      String.fromCharCode(
        BASE64URL_ALPHABET.charCodeAt((triple >> 18) & 63),
        BASE64URL_ALPHABET.charCodeAt((triple >> 12) & 63),
        BASE64URL_ALPHABET.charCodeAt((triple >> 6) & 63),
      ),
    );
  }
  return chunks.join("");
}

function sextet(code: number): number {
  const value = code < 128 ? BASE64URL_LOOKUP[code]! : -1;
  if (value < 0) {
    throw new Error("envsafe-crypto: invalid base64url input.");
  }
  return value;
}

/** Inverse of bytesToBase64url. Throws on an invalid length or character. */
export function base64urlToBytes(input: string): Uint8Array {
  const len = input.length;
  const remainder = len % 4;
  if (remainder === 1) {
    throw new Error("envsafe-crypto: invalid base64url length.");
  }
  const outLength = Math.floor(len / 4) * 3 + (remainder === 0 ? 0 : remainder - 1);
  const out = new Uint8Array(outLength);
  let o = 0;
  let i = 0;
  for (; i + 4 <= len; i += 4) {
    const quad =
      (sextet(input.charCodeAt(i)) << 18) |
      (sextet(input.charCodeAt(i + 1)) << 12) |
      (sextet(input.charCodeAt(i + 2)) << 6) |
      sextet(input.charCodeAt(i + 3));
    out[o++] = (quad >> 16) & 0xff;
    out[o++] = (quad >> 8) & 0xff;
    out[o++] = quad & 0xff;
  }
  if (remainder === 2) {
    const s0 = sextet(input.charCodeAt(i));
    const s1 = sextet(input.charCodeAt(i + 1));
    // A 2-char tail carries 1 byte. Only the top 2 bits of the last sextet are
    // used, so the low 4 bits must be zero for a canonical encoding. Reject any
    // non-canonical tail so each byte sequence has exactly one valid encoding.
    if ((s1 & 0x0f) !== 0) {
      throw new Error("envsafe-crypto: non-canonical base64url input.");
    }
    const quad = (s0 << 18) | (s1 << 12);
    out[o++] = (quad >> 16) & 0xff;
  } else if (remainder === 3) {
    const s0 = sextet(input.charCodeAt(i));
    const s1 = sextet(input.charCodeAt(i + 1));
    const s2 = sextet(input.charCodeAt(i + 2));
    // A 3-char tail carries 2 bytes. Only the top 4 bits of the last sextet are
    // used, so the low 2 bits must be zero for a canonical encoding.
    if ((s2 & 0x03) !== 0) {
      throw new Error("envsafe-crypto: non-canonical base64url input.");
    }
    const quad = (s0 << 18) | (s1 << 12) | (s2 << 6);
    out[o++] = (quad >> 16) & 0xff;
    out[o++] = (quad >> 8) & 0xff;
  }
  return out;
}
