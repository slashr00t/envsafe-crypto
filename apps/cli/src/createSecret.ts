/**
 * The single network seam. It POSTs the ciphertext envelope and metadata to the
 * create endpoint and returns the new secret id. Native fetch, zero
 * dependencies.
 *
 * TODO(create-endpoint): The SaaS create endpoint does not exist yet, but the
 * architect has set the contract this seam implements. Build the server to match:
 *
 *   POST {apiBase}/api/secrets
 *   Request body (JSON):
 *     {
 *       "envelope": { "v": 1, "alg": "A256GCM", "iv": "<b64url>", "ct": "<b64url>" },
 *       "expires_in": <integer seconds, relative>,
 *       "max_views": <positive integer>
 *     }
 *   Response (JSON): { "id": "<opaque string>" }
 *
 * expires_in is relative seconds. The server computes expires_at from its own
 * clock; the client never sends an absolute timestamp. Until the endpoint is
 * live this seam is exercised only through mocks and a stubbed fetch in tests.
 */

import type { CreatePayload } from "./push.ts";

const CREATE_PATH = "/api/secrets";

export async function createSecret(
  apiBase: string,
  payload: CreatePayload,
): Promise<{ id: string }> {
  const url = new URL(CREATE_PATH, apiBase);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (cause) {
    throw new Error(`could not reach the api at ${url.origin}.`, { cause });
  }

  if (!response.ok) {
    throw new Error(`create failed with status ${response.status}.`);
  }

  let data: unknown;
  try {
    data = await response.json();
  } catch (cause) {
    throw new Error("create returned a response that was not json.", { cause });
  }

  if (
    typeof data !== "object" ||
    data === null ||
    typeof (data as { id?: unknown }).id !== "string" ||
    (data as { id: string }).id.length === 0
  ) {
    throw new Error("create returned no id.");
  }

  return { id: (data as { id: string }).id };
}
