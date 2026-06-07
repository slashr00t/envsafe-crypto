#!/usr/bin/env node
/**
 * The envsafe CLI entry point. It wires the real input readers and the real
 * network seam, runs the requested command, and maps the result to stdout,
 * stderr and an exit code.
 *
 * Only the share link is written to stdout, so the output is safe to pipe. All
 * status and all errors go to stderr.
 */

import { readFile as fsReadFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { parseArgs, USAGE } from "./args.ts";
import { runPush, type PushDeps } from "./push.ts";
import { createSecret } from "./createSecret.ts";

async function readStdin(): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

async function readFileBytes(path: string): Promise<Uint8Array> {
  return new Uint8Array(await fsReadFile(path));
}

const realDeps: PushDeps = {
  createSecret,
  readFile: readFileBytes,
  readStdin,
};

export interface Io {
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
}

const realIo: Io = {
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
};

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Runs the CLI and returns the process exit code. Dependencies and IO are
 * injectable so the whole flow can be driven offline in tests.
 */
export async function main(
  argv: readonly string[],
  env: Record<string, string | undefined>,
  deps: PushDeps = realDeps,
  io: Io = realIo,
): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs(argv, env);
  } catch (error) {
    io.err(`envsafe: ${messageOf(error)}`);
    io.err("");
    io.err(USAGE);
    return 2;
  }

  if (parsed.kind === "help") {
    io.out(USAGE);
    return 0;
  }

  try {
    io.err("envsafe: encrypting locally and creating the secret...");
    const link = await runPush(parsed.options, deps);
    io.out(link);
    return 0;
  } catch (error) {
    io.err(`envsafe: ${messageOf(error)}`);
    return 1;
  }
}

// Run only when executed directly as the bin, not when imported by a test.
const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  process.exitCode = await main(process.argv.slice(2), process.env);
}
