/**
 * Tiny hand rolled argument parser for the single push command. No runtime
 * dependency. It returns either the help mode or a validated set of push
 * options. Anything malformed throws so the caller can report it and exit
 * non-zero.
 */

import { parseDuration } from "./duration.ts";

const DEFAULT_API_BASE = "https://envsafe.app";
const DEFAULT_EXPIRES = "24h";
const DEFAULT_MAX_VIEWS = 1;

export interface PushOptions {
  /** The file to read, or undefined to read stdin. */
  readonly file: string | undefined;
  /** Expiry in seconds, already validated against the cap. */
  readonly expiresSeconds: number;
  /** Views before the secret burns. A positive integer. */
  readonly maxViews: number;
  /** The API base URL the create request goes to. */
  readonly apiBase: string;
}

export type ParseResult =
  | { readonly kind: "help" }
  | { readonly kind: "push"; readonly options: PushOptions };

const FLAGS_WITH_VALUES = new Set(["--expires", "--max-views", "--api"]);

function parseMaxViews(raw: string): number {
  if (!/^\d+$/.test(raw)) {
    throw new Error(`invalid --max-views "${raw}". Use a positive integer.`);
  }
  const value = Number(raw);
  if (value < 1) {
    throw new Error(`invalid --max-views "${raw}". The value must be at least 1.`);
  }
  return value;
}

export function parseArgs(
  argv: readonly string[],
  env: Record<string, string | undefined>,
): ParseResult {
  if (argv.includes("--help") || argv.includes("-h")) {
    return { kind: "help" };
  }

  const command = argv[0];
  if (command === undefined) {
    throw new Error("no command given. Try: envsafe push [file]");
  }
  if (command !== "push") {
    throw new Error(`unknown command "${command}". The only command is push.`);
  }

  let file: string | undefined;
  let expires = DEFAULT_EXPIRES;
  let maxViewsRaw: string | undefined;
  let api: string | undefined;

  for (let i = 1; i < argv.length; i++) {
    const token = argv[i]!;

    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      const name = eq === -1 ? token : token.slice(0, eq);
      let value = eq === -1 ? undefined : token.slice(eq + 1);

      if (!FLAGS_WITH_VALUES.has(name)) {
        throw new Error(`unknown flag "${name}".`);
      }
      if (value === undefined) {
        value = argv[i + 1];
        i++;
      }
      if (value === undefined) {
        throw new Error(`flag "${name}" needs a value.`);
      }

      if (name === "--expires") expires = value;
      else if (name === "--max-views") maxViewsRaw = value;
      else api = value;
      continue;
    }

    if (token.startsWith("-") && token !== "-") {
      throw new Error(`unknown flag "${token}".`);
    }

    if (file !== undefined) {
      throw new Error("only one file argument is allowed.");
    }
    file = token;
  }

  const options: PushOptions = {
    file,
    expiresSeconds: parseDuration(expires),
    maxViews: maxViewsRaw === undefined ? DEFAULT_MAX_VIEWS : parseMaxViews(maxViewsRaw),
    apiBase: api ?? env["ENVSAFE_API"] ?? DEFAULT_API_BASE,
  };
  return { kind: "push", options };
}

/** The usage string shown by --help and on a usage error. */
export const USAGE = `envsafe push [file] [options]

Encrypt a secret locally and print a one-time share link. Encryption happens on
your machine with @envsafe/crypto. The key lives only in the link fragment after
the # and is never sent to the server.

Arguments:
  file                  Read the secret from this file. If omitted, read stdin.

Options:
  --expires <duration>  Lifetime before the secret expires, like 1h, 24h or 7d.
                        Default 24h. Maximum 7d.
  --max-views <n>       Views before the secret burns. A positive integer.
                        Default 1.
  --api <url>           API base URL. Default $ENVSAFE_API or https://envsafe.app.
  -h, --help            Show this help.

Examples:
  envsafe push .env
  cat .env | envsafe push
  envsafe push secret.txt --expires 1h --max-views 3

Only the share link is written to stdout, so it is safe to pipe. All status goes
to stderr.`;
