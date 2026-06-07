# @envsafe/crypto

The frozen client-side crypto core for envsafe. AES-GCM-256 with a versioned
envelope, zero runtime dependencies, pure WebCrypto. Runs in browsers and in
Node 20 and newer.

The server never sees your plaintext or your key. The key is generated on the
client and travels only in a URL fragment, which browsers never send to a server.
The envelope you can store carries ciphertext and a header, never key material.

```bash
npm install @envsafe/crypto
```

```ts
import { generateKey, encrypt, decrypt } from "@envsafe/crypto";

const key = await generateKey();
const envelope = await encrypt(key, "my secret");
const text = await decrypt(key, envelope); // "my secret"
```

The public API and the wire formats are a frozen contract. See
[INTERFACE.md](./INTERFACE.md) for the full list of exports, the envelope and
wrapped key formats, and the failure behavior.

## Properties

- AES-GCM-256, a fresh 256-bit key per secret and a fresh 96-bit IV per message.
- The header `v;alg;iv` is bound as GCM additional authenticated data, so a
  tampered header fails closed.
- Passphrase wrapping with PBKDF2-HMAC-SHA256 at 600000 iterations, with the KDF
  parameters stored so they can migrate later.
- Zero runtime dependencies. The only hand rolled code is base64url, covered by a
  fuzz test.

## License

Apache-2.0.
