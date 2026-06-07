/**
 * Tiny duration parser. Accepts values like 1h, 24h, 7d. Hand rolled so the CLI
 * carries no runtime dependency for it.
 */

/** The anonymous tier expiry cap. Seven days in seconds. */
export const MAX_EXPIRES_SECONDS = 7 * 24 * 60 * 60;

const UNIT_SECONDS: Readonly<Record<string, number>> = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 24 * 60 * 60,
};

/**
 * Parses a duration string into a whole number of seconds.
 *
 * The format is a positive integer followed by a unit: s, m, h or d. The result
 * is capped at seven days, the anonymous tier limit. Anything longer, malformed,
 * zero or negative is rejected so a bad value fails early with a clear message.
 */
export function parseDuration(input: string): number {
  const match = /^(\d+)([smhd])$/.exec(input);
  if (match === null) {
    throw new Error(
      `invalid duration "${input}". Use a value like 1h, 24h or 7d.`,
    );
  }
  const amount = Number(match[1]);
  const unit = match[2]!;
  if (amount <= 0) {
    throw new Error(`invalid duration "${input}". The value must be positive.`);
  }
  const seconds = amount * UNIT_SECONDS[unit]!;
  if (seconds > MAX_EXPIRES_SECONDS) {
    throw new Error(
      `expiry "${input}" exceeds the 7d maximum for the anonymous tier.`,
    );
  }
  return seconds;
}
