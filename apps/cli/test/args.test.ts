import { test } from "node:test";
import assert from "node:assert/strict";

import { parseArgs } from "../src/args.ts";

const NO_ENV: Record<string, string | undefined> = {};

function push(argv: string[], env: Record<string, string | undefined> = NO_ENV) {
  const result = parseArgs(argv, env);
  assert.equal(result.kind, "push");
  if (result.kind !== "push") throw new Error("unreachable");
  return result.options;
}

test("treats --help and -h as the help mode", () => {
  assert.equal(parseArgs(["--help"], NO_ENV).kind, "help");
  assert.equal(parseArgs(["-h"], NO_ENV).kind, "help");
  assert.equal(parseArgs(["push", "--help"], NO_ENV).kind, "help");
});

test("parses a file positional argument", () => {
  assert.equal(push(["push", ".env"]).file, ".env");
});

test("uses stdin when no file is given", () => {
  assert.equal(push(["push"]).file, undefined);
});

test("applies defaults for expiry, views and api base", () => {
  const options = push(["push", ".env"]);
  assert.equal(options.expiresSeconds, 86400);
  assert.equal(options.maxViews, 1);
  assert.equal(options.apiBase, "https://envsafe.app");
});

test("parses --expires in space and equals form", () => {
  assert.equal(push(["push", "--expires", "1h"]).expiresSeconds, 3600);
  assert.equal(push(["push", "--expires=7d"]).expiresSeconds, 604800);
});

test("rejects an expiry over the 7d cap", () => {
  assert.throws(() => parseArgs(["push", "--expires", "30d"], NO_ENV), /7d/);
});

test("max-views defaults to 1 and accepts a positive integer", () => {
  assert.equal(push(["push"]).maxViews, 1);
  assert.equal(push(["push", "--max-views", "5"]).maxViews, 5);
});

test("rejects an invalid max-views", () => {
  assert.throws(() => parseArgs(["push", "--max-views", "0"], NO_ENV));
  assert.throws(() => parseArgs(["push", "--max-views", "-1"], NO_ENV));
  assert.throws(() => parseArgs(["push", "--max-views", "1.5"], NO_ENV));
  assert.throws(() => parseArgs(["push", "--max-views", "abc"], NO_ENV));
});

test("resolves the api base from --api, then env, then the default", () => {
  assert.equal(push(["push", "--api", "http://localhost:8787"]).apiBase, "http://localhost:8787");
  assert.equal(
    push(["push"], { ENVSAFE_API: "https://staging.envsafe.app" }).apiBase,
    "https://staging.envsafe.app",
  );
  // An explicit flag beats the environment variable.
  assert.equal(
    push(["push", "--api", "http://localhost:8787"], { ENVSAFE_API: "https://staging.envsafe.app" })
      .apiBase,
    "http://localhost:8787",
  );
});

test("rejects an unknown flag", () => {
  assert.throws(() => parseArgs(["push", "--nope"], NO_ENV));
});

test("rejects a flag that is missing its value", () => {
  assert.throws(() => parseArgs(["push", "--expires"], NO_ENV));
});

test("rejects an unknown command", () => {
  assert.throws(() => parseArgs(["pull"], NO_ENV));
});

test("rejects when no command is given", () => {
  assert.throws(() => parseArgs([], NO_ENV));
});

test("rejects more than one positional argument", () => {
  assert.throws(() => parseArgs(["push", "a.env", "b.env"], NO_ENV));
});
