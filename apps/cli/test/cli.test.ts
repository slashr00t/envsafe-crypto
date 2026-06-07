import { test } from "node:test";
import assert from "node:assert/strict";

import { main } from "../src/cli.ts";
import type { PushDeps } from "../src/push.ts";

const enc = new TextEncoder();

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l: string) => out.push(l), err: (l: string) => err.push(l) }, out, err };
}

function deps(opts: { stdin?: Uint8Array; id?: string; throws?: Error } = {}): PushDeps {
  return {
    createSecret: async () => {
      if (opts.throws) throw opts.throws;
      return { id: opts.id ?? "id1" };
    },
    readFile: async () => opts.stdin ?? enc.encode("x"),
    readStdin: async () => opts.stdin ?? enc.encode("x"),
  };
}

test("--help prints usage to stdout and exits 0", async () => {
  const { io, out, err } = capture();
  const code = await main(["--help"], {}, deps(), io);
  assert.equal(code, 0);
  assert.ok(out.join("\n").includes("envsafe push"));
  assert.equal(err.length, 0);
});

test("a successful push prints only the link to stdout", async () => {
  const { io, out, err } = capture();
  const code = await main(
    ["push"],
    {},
    deps({ stdin: enc.encode("hello"), id: "abc" }),
    io,
  );
  assert.equal(code, 0);
  // Exactly one line on stdout, and it is the link.
  assert.equal(out.length, 1);
  assert.ok(out[0]!.startsWith("https://envsafe.app/s/abc#"));
  // Status goes to stderr, so it never pollutes the pipeable stdout.
  assert.ok(err.length >= 1);
});

test("a usage error goes to stderr and exits 2", async () => {
  const { io, out, err } = capture();
  const code = await main(["pull"], {}, deps(), io);
  assert.equal(code, 2);
  assert.equal(out.length, 0);
  assert.ok(err.join("\n").length > 0);
});

test("an invalid flag value exits 2 with nothing on stdout", async () => {
  const { io, out } = capture();
  const code = await main(["push", "--max-views", "0"], {}, deps(), io);
  assert.equal(code, 2);
  assert.equal(out.length, 0);
});

test("a network failure goes to stderr and exits 1", async () => {
  const { io, out, err } = capture();
  const code = await main(
    ["push"],
    {},
    deps({ stdin: enc.encode("hello"), throws: new Error("could not reach the api") }),
    io,
  );
  assert.equal(code, 1);
  assert.equal(out.length, 0);
  assert.ok(err.join("\n").includes("could not reach the api"));
});

test("honors ENVSAFE_API for the link origin", async () => {
  const { io, out } = capture();
  const code = await main(
    ["push"],
    { ENVSAFE_API: "http://localhost:8787" },
    deps({ stdin: enc.encode("hello"), id: "loc" }),
    io,
  );
  assert.equal(code, 0);
  assert.ok(out[0]!.startsWith("http://localhost:8787/s/loc#"));
});
