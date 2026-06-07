# envsafe-crypto

The open source trust artifacts behind envsafe. This repository holds the parts
you should be able to read, audit and run yourself before you trust us with a
secret: the crypto core and the command line tool that uses it.

If you are going to send a secret through a service, you should not have to take
the service at its word. You should be able to read the code that locks the
secret, confirm the server never sees the key, and run it on your own machine.
That code lives here, under Apache-2.0.

## The trust model

envsafe is built so that the server never sees your plaintext and never sees
your key.

- Encryption and decryption happen on the client, in the browser or in the CLI.
- The key is generated fresh for each secret and never leaves the client except
  inside the URL fragment, the part of a link after the `#`. Browsers do not send
  the fragment to the server, so the key never reaches us.
- The thing the server can store, the envelope, contains the ciphertext, the
  nonce and a small version header. It contains no key material.
- The header is bound into the ciphertext as authenticated data, so a tampered
  header fails closed instead of decrypting to something wrong.

Put plainly: we hold a sealed box and the recipient holds the only key, carried
in a link we never get to read.

## What is in this repository

This is an npm workspaces monorepo.

- `packages/crypto` is `@envsafe/crypto`, the frozen crypto core. Pure WebCrypto,
  zero runtime dependencies, runs in browsers and in Node 20 and newer.
- `apps/cli` is the command line tool. It is a placeholder for now and is not
  built yet.

## @envsafe/crypto

```bash
npm install @envsafe/crypto
```

```ts
import {
  generateKey,
  encrypt,
  decrypt,
  keyToFragment,
  buildShareLink,
  keyFromFragment,
} from "@envsafe/crypto";

// Lock a secret.
const key = await generateKey();
const envelope = await encrypt(key, "my database password");

// The envelope is safe to store on a server. It has no key material.
// The key travels in the link fragment, which the server never sees.
const link = buildShareLink("https://envsafe.app/s/abc123", await keyToFragment(key));

// The recipient opens the link and recovers the key from the fragment.
const recovered = await keyFromFragment(link);
console.log(await decrypt(recovered, envelope)); // "my database password"
```

### The envelope

```json
{ "v": 1, "alg": "A256GCM", "iv": "base64url", "ct": "base64url" }
```

AES-GCM-256 with a fresh 256-bit key per secret and a fresh 96-bit IV per
message. The header `v;alg;iv` is bound as GCM additional authenticated data, so
any change to the version, the algorithm or the nonce makes decryption fail.

### Passphrase wrapping

When you want a passphrase instead of a link fragment, the key can be wrapped
with PBKDF2-HMAC-SHA256 at 600000 iterations. The wrapped key stores its own KDF
parameters so it can move to a stronger KDF later without breaking existing data.

```ts
import { wrapKeyWithPassphrase, unwrapKeyWithPassphrase } from "@envsafe/crypto";

const wrapped = await wrapKeyWithPassphrase(key, "a strong passphrase");
const back = await unwrapKeyWithPassphrase(wrapped, "a strong passphrase");
```

## Security posture

- Zero runtime dependencies in the crypto core. The whole attack surface is the
  code in this repository plus the platform WebCrypto implementation.
- WebCrypto only. The one piece of hand rolled code is base64url, which is
  covered by a fuzz test across input lengths 0 to 129.
- The public API and the wire formats are a frozen contract. See
  `packages/crypto/INTERFACE.md`. A breaking change requires a version bump and a
  migration path, so old envelopes keep decrypting.
- `npm audit` is required to be clean of high and critical findings.
- Releases are published with npm provenance.

## Development

```bash
npm install
npm test          # runs the crypto test suite
npm run typecheck
npm run build
npm run audit
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
