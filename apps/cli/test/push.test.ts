import { test } from "node:test";
import assert from "node:assert/strict";

import { keyFromFragment, decryptBytes } from "@envsafe/crypto";

import { runPush, MAX_SECRET_BYTES, type CreatePayload, type PushDeps } from "../src/push.ts";
import type { PushOptions } from "../src/args.ts";

const enc = new TextEncoder();

function options(overrides: Partial<PushOptions> = {}): PushOptions {
  return {
    file: undefined,
    expiresSeconds: 86400,
    maxViews: 1,
    apiBase: "https://envsafe.app",
    ...overrides,
  };
}

/**
 * A recording mock for the network seam. It captures the payload it was asked to
 * send and returns a fixed id. No real network is touched.
 */
function mockCreate(id = "abc123") {
  const calls: { apiBase: string; payload: CreatePayload }[] = [];
  const createSecret: PushDeps["createSecret"] = async (apiBase, payload) => {
    calls.push({ apiBase, payload });
    return { id };
  };
  return { createSecret, calls };
}

function depsFor(
  createSecret: PushDeps["createSecret"],
  source: { file?: Uint8Array; stdin?: Uint8Array },
): PushDeps {
  return {
    createSecret,
    readFile: async () => {
      if (source.file === undefined) throw new Error("readFile should not be called");
      return source.file;
    },
    readStdin: async () => {
      if (source.stdin === undefined) throw new Error("readStdin should not be called");
      return source.stdin;
    },
  };
}

test("reads the secret from a file when a path is given", async () => {
  const { createSecret, calls } = mockCreate();
  const deps = depsFor(createSecret, { file: enc.encode("from-file") });
  await runPush(options({ file: "secret.env" }), deps);
  assert.equal(calls.length, 1);
});

test("reads the secret from stdin when no file is given", async () => {
  const { createSecret, calls } = mockCreate();
  const deps = depsFor(createSecret, { stdin: enc.encode("from-stdin") });
  await runPush(options(), deps);
  assert.equal(calls.length, 1);
});

test("posts ciphertext and metadata only, never the key", async () => {
  const { createSecret, calls } = mockCreate();
  const deps = depsFor(createSecret, { stdin: enc.encode("super secret value") });
  const link = await runPush(options({ expiresSeconds: 3600, maxViews: 2 }), deps);

  const payload = calls[0]!.payload;
  // The crypto fields are nested under envelope as one unit, alongside the two
  // metadata fields. No key field of any name. expires_in is relative seconds.
  assert.deepEqual(Object.keys(payload).sort(), ["envelope", "expires_in", "max_views"]);
  assert.deepEqual(Object.keys(payload.envelope).sort(), ["alg", "ct", "iv", "v"]);
  assert.equal(payload.expires_in, 3600);
  assert.equal(payload.max_views, 2);

  // The key only lives in the link fragment. It must not appear in the request.
  const fragment = link.slice(link.lastIndexOf("#") + 1);
  assert.ok(!JSON.stringify(payload).includes(fragment), "key fragment leaked into the payload");
  // The ciphertext is not the plaintext.
  assert.ok(!JSON.stringify(payload).includes("super secret value"));
});

test("the printed link round-trips: its fragment decrypts the original", async () => {
  const original = enc.encode("DATABASE_URL=postgres://localhost/app");
  const { createSecret, calls } = mockCreate("xyz789");
  const deps = depsFor(createSecret, { stdin: original });
  const link = await runPush(options({ apiBase: "https://envsafe.app" }), deps);

  // The link points at the returned id and carries the key after the #.
  assert.ok(link.startsWith("https://envsafe.app/s/xyz789#"));

  const key = await keyFromFragment(link);
  const recovered = await decryptBytes(key, calls[0]!.payload.envelope);
  assert.deepEqual(recovered, original);
});

test("builds the link from the api base origin and the returned id", async () => {
  const { createSecret } = mockCreate("id-1");
  const deps = depsFor(createSecret, { stdin: enc.encode("x") });
  const link = await runPush(options({ apiBase: "http://localhost:8787/" }), deps);
  // A trailing slash on the api base is not doubled.
  assert.ok(link.startsWith("http://localhost:8787/s/id-1#"));
});

test("rejects an oversized payload before encrypting", async () => {
  let createCalled = false;
  const createSecret: PushDeps["createSecret"] = async (_a, _p) => {
    createCalled = true;
    return { id: "nope" };
  };
  const tooBig = new Uint8Array(MAX_SECRET_BYTES + 1);
  const deps = depsFor(createSecret, { stdin: tooBig });
  await assert.rejects(() => runPush(options(), deps), /256/);
  assert.equal(createCalled, false, "must reject before any network call");
});

test("accepts a payload exactly at the cap", async () => {
  const { createSecret, calls } = mockCreate();
  const atCap = new Uint8Array(MAX_SECRET_BYTES);
  const deps = depsFor(createSecret, { stdin: atCap });
  await runPush(options(), deps);
  assert.equal(calls.length, 1);
});

test("rejects an empty secret", async () => {
  const { createSecret } = mockCreate();
  const deps = depsFor(createSecret, { stdin: new Uint8Array(0) });
  await assert.rejects(() => runPush(options(), deps));
});
