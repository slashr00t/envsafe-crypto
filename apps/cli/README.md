# @envsafe/cli

The envsafe command line tool. Encrypt a secret on your own machine and get back
a one-time share link. Encryption happens locally with
[`@envsafe/crypto`](../../packages/crypto). The key lives only in the link
fragment after the `#` and is never sent to the server.

A security aware user runs this instead of the web app. There is no served
bundle to re-trust on each use. You read this code once, you run it, and the
ciphertext is the only thing that leaves your machine.

## Status

This is v1. The create endpoint that stores the ciphertext does not exist yet, so
the single network call is intentionally stubbed behind one function. Everything
else is complete and tested offline. The request and response shape is the
intended contract and is marked with a TODO so it can be reconciled with the real
endpoint when it lands.

## Install

Once published:

```bash
npx @envsafe/cli push .env
# or install it globally
npm install -g @envsafe/cli
```

## Usage

```bash
envsafe push [file] [options]
```

`push` reads the secret from a file, or from stdin when no file is given. Both of
these work:

```bash
envsafe push .env
cat .env | envsafe push
```

It encrypts the contents, sends only the ciphertext envelope and the metadata to
the create endpoint, then prints the share link. Only the link goes to stdout, so
it is safe to pipe. All status goes to stderr.

```bash
LINK=$(envsafe push .env)
```

### Options

| Flag                   | Default                        | Notes                                  |
| ---------------------- | ------------------------------ | -------------------------------------- |
| `--expires <duration>` | `24h`                          | Values like `1h`, `24h`, `7d`. Max `7d`. |
| `--max-views <n>`      | `1`                            | Burn after read. A positive integer.   |
| `--api <url>`          | `$ENVSAFE_API` or `https://envsafe.app` | API base URL.                 |
| `-h`, `--help`         |                                | Show usage.                            |

The expiry is capped at seven days, the anonymous tier limit. A longer value is
rejected with a clear message. The secret is capped at 256KB client side and an
oversized secret is rejected before any encryption or network call.

## How the trust model holds

- A fresh AES-GCM-256 key is generated for each secret.
- The contents are encrypted locally into a versioned envelope.
- The POST body nests the envelope `{ v, alg, iv, ct }` under `envelope`, with
  `expires_in` in relative seconds and `max_views`. It carries no key material.
- The key is turned into the link fragment and appended after the `#`. Browsers
  do not send the fragment to a server, so the key never reaches the service.

## Development

The CLI resolves `@envsafe/crypto` through the workspace during development. Build
the crypto core first so its `dist` exists.

```bash
npm run build --workspace @envsafe/crypto
npm test --workspace @envsafe/cli         # node:test, runs offline
npm run typecheck --workspace @envsafe/cli
npm run build --workspace @envsafe/cli     # emits dist with an executable bin
```

Run it without installing:

```bash
node src/cli.ts push .env --api http://localhost:8787   # dev, runs the TS source
node dist/cli.js push .env                                # after a build
```

## License

Apache-2.0.
