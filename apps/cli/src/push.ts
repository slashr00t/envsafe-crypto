/**
 * The push command. Reads a secret, encrypts it locally with the frozen
 * @envsafe/crypto core, sends only the ciphertext envelope and metadata to the
 * create endpoint, then builds the share link so the key lives only in the
 * fragment.
 *
 * The network call and the input readers are injected through PushDeps so the
 * whole flow is testable offline with no real network.
 */

import {
  generateKey,
  encryptBytes,
  keyToFragment,
  buildShareLink,
  type Envelope,
} from "@envsafe/crypto";

import type { PushOptions } from "./args.ts";

/** The client cap on the secret size. Matches the server cap we will set. */
export const MAX_SECRET_BYTES = 256 * 1024;

/**
 * The body sent to the create endpoint. The crypto fields are nested under
 * envelope as one unit, alongside the two pieces of metadata. It carries no key
 * material. See the agreed contract in createSecret.ts.
 */
export interface CreatePayload {
  readonly envelope: Envelope;
  /** Lifetime in seconds, relative. The server derives the absolute expiry. */
  readonly expires_in: number;
  /** Views before the secret burns. */
  readonly max_views: number;
}

export interface PushDeps {
  readonly createSecret: (
    apiBase: string,
    payload: CreatePayload,
  ) => Promise<{ id: string }>;
  readonly readFile: (path: string) => Promise<Uint8Array>;
  readonly readStdin: () => Promise<Uint8Array>;
}

function stripTrailingSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

/**
 * Runs the push flow and returns the share link. The key is generated here,
 * carried into the returned link fragment, and never placed in the payload.
 */
export async function runPush(options: PushOptions, deps: PushDeps): Promise<string> {
  const bytes =
    options.file !== undefined ? await deps.readFile(options.file) : await deps.readStdin();

  if (bytes.length === 0) {
    throw new Error("the secret is empty. Provide a file or pipe data on stdin.");
  }
  if (bytes.length > MAX_SECRET_BYTES) {
    throw new Error(
      `the secret is ${bytes.length} bytes, over the 256KB limit. Send a smaller secret.`,
    );
  }

  const key = await generateKey();
  const envelope = await encryptBytes(key, bytes);

  const payload: CreatePayload = {
    envelope,
    expires_in: options.expiresSeconds,
    max_views: options.maxViews,
  };

  const { id } = await deps.createSecret(options.apiBase, payload);
  if (typeof id !== "string" || id.length === 0) {
    throw new Error("the create endpoint did not return an id.");
  }

  const fragment = await keyToFragment(key);
  return buildShareLink(`${stripTrailingSlash(options.apiBase)}/s/${id}`, fragment);
}
