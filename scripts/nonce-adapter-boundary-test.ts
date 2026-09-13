/**
 * Adapter boundary tests for the durable nonce store window guard.
 *
 * Pure, offline, no database, no network, no secrets. Asserts that only an
 * exact 300000 ms window is accepted — the previously accepted rounded band
 * 299001..300000 ms must be rejected, since a shorter retention would let a
 * nonce be reclaimed while the verifier's 60 s timestamp window still accepts
 * the same request.
 */
import {
  FIXED_TTL_MS,
  assertFixedRetentionWindow,
} from "../src/lib/custody/nonce-store.server";

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean) {
  if (ok) {
    pass += 1;
    console.log(`PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL  ${name}`);
  }
}

const now = 1_700_000_000_000;

check("fixed retention window is exactly 300000 ms", FIXED_TTL_MS === 300_000);

function accepts(delta: number): boolean {
  try {
    assertFixedRetentionWindow(now, now + delta);
    return true;
  } catch {
    return false;
  }
}

check("exact 300000 ms window accepted", accepts(300_000));

for (const delta of [299_001, 299_500, 299_999, 300_001, 299_000, 60_000, 1_000, 0, -1, 3_600_000]) {
  check(`window ${delta} ms rejected (no rounding, no clamping)`, !accepts(delta));
}

check("NaN window rejected", !accepts(Number.NaN));
check(
  "non-finite endpoints rejected",
  (() => {
    try {
      assertFixedRetentionWindow(Number.POSITIVE_INFINITY, Number.POSITIVE_INFINITY);
      return false;
    } catch {
      return true;
    }
  })(),
);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
