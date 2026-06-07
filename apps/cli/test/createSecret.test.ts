import { test } from "node:test";
import assert from "node:assert/strict";

import { createSecret } from "../src/createSecret.ts";
import type { CreatePayload } from "../src/push.ts";

const PAYLOAD: CreatePayload = {
  envelope: { v: 1, alg: "A256GCM", iv: "aaaa", ct: "bbbb" },
  expires_in: 3600,
  max_views: 1,
};

type FetchFn = typeof globalThis.fetch;

/** Swap globalThis.fetch for a stub, run the body, then restore. No network. */
async function withFetch(stub: FetchFn, body: () => Promise<void>): Promise<void> {
  const real = globalThis.fetch;
  globalThis.fetch = stub;
  try {
    await body();
  } finally {
    globalThis.fetch = real;
  }
}

test("posts the payload as json and returns the id", async () => {
  let seenUrl: string | undefined;
  let seenInit: RequestInit | undefined;
  const stub: FetchFn = async (input, init) => {
    seenUrl = String(input);
    seenInit = init;
    return new Response(JSON.stringify({ id: "srv-id" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await withFetch(stub, async () => {
    const result = await createSecret("https://api.test", PAYLOAD);
    assert.deepEqual(result, { id: "srv-id" });
    assert.equal(seenUrl, "https://api.test/api/secrets");
    assert.equal(seenInit?.method, "POST");
    const sent = JSON.parse(String(seenInit?.body));
    assert.equal(sent.envelope.ct, "bbbb");
    assert.equal(sent.expires_in, 3600);
  });
});

test("throws on a non-ok response", async () => {
  const stub: FetchFn = async () => new Response("nope", { status: 500 });
  await withFetch(stub, async () => {
    await assert.rejects(() => createSecret("https://api.test", PAYLOAD));
  });
});

test("throws when the response has no id", async () => {
  const stub: FetchFn = async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  await withFetch(stub, async () => {
    await assert.rejects(() => createSecret("https://api.test", PAYLOAD));
  });
});
