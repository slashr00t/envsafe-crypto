import { test } from "node:test";
import assert from "node:assert/strict";

import { parseDuration, MAX_EXPIRES_SECONDS } from "../src/duration.ts";

test("parses hour and day durations to seconds", () => {
  assert.equal(parseDuration("1h"), 3600);
  assert.equal(parseDuration("24h"), 86400);
  assert.equal(parseDuration("7d"), 604800);
});

test("parses second and minute units", () => {
  assert.equal(parseDuration("30s"), 30);
  assert.equal(parseDuration("15m"), 900);
});

test("accepts exactly the 7d cap", () => {
  assert.equal(parseDuration("7d"), MAX_EXPIRES_SECONDS);
  assert.equal(parseDuration("168h"), MAX_EXPIRES_SECONDS);
});

test("rejects durations over the 7d cap", () => {
  assert.throws(() => parseDuration("8d"), /7d/);
  assert.throws(() => parseDuration("169h"), /7d/);
  assert.throws(() => parseDuration("10000h"), /7d/);
});

test("rejects a zero or negative duration", () => {
  assert.throws(() => parseDuration("0h"));
  assert.throws(() => parseDuration("-1h"));
});

test("rejects an invalid duration format", () => {
  assert.throws(() => parseDuration(""));
  assert.throws(() => parseDuration("24"));
  assert.throws(() => parseDuration("1.5h"));
  assert.throws(() => parseDuration("1y"));
  assert.throws(() => parseDuration("h"));
  assert.throws(() => parseDuration("abc"));
});
