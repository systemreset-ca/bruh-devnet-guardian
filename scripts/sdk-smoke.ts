/**
 * Runner for the server-only SDK compatibility smoke checks.
 * Prints booleans only — never seeds, keys, signatures or ciphertext.
 *
 *   bun run scripts/sdk-smoke.ts
 */
import { runSdkCompatibilitySmoke } from "../src/lib/custody/sdk-smoke.server";

const report = await runSdkCompatibilitySmoke();
for (const [name, ok] of Object.entries(report.checks)) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
}
console.log(`\nnetwork=${report.network} broadcast=${report.broadcast} passed=${report.passed}`);
process.exit(report.passed ? 0 : 1);
