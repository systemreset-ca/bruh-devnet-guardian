/**
 * Trusted live probe against the DEPLOYED Worker runtime.
 *
 * Reads the injected server credentials from the environment
 * (SIGNER_CALLER_SECRET, SIGNER_CALLER_KEY_ID) and signs one POST with an empty
 * JSON body. It NEVER prints the secret, the key ID, the signature, the nonce or
 * any request header — only the HTTP status and the returned booleans/counts.
 *
 * Usage: BASE_URL=https://<host> bun run scripts/live-diagnostic-probe.ts
 */
import {
  HEADER_KEY_ID,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  bodyDigestHex,
  canonicalString,
  newNonce,
  signCanonical,
} from "../src/lib/custody/request-auth.server";

const PATH = "/api/public/signer/selftest";
const baseUrl = process.env["BASE_URL"];
const secret = process.env["SIGNER_CALLER_SECRET"];
const keyId = process.env["SIGNER_CALLER_KEY_ID"];

if (!baseUrl) {
  console.log("FAIL  BASE_URL is not set");
  process.exit(1);
}
if (!secret || !keyId) {
  console.log("FAIL  caller credentials are not injected in this environment");
  process.exit(1);
}

const body = "{}";
const timestamp = String(Date.now());
const nonce = newNonce();
const signature = signCanonical(
  secret,
  canonicalString({
    keyId,
    method: "POST",
    path: PATH,
    timestamp,
    nonce,
    bodyDigestHex: bodyDigestHex(body),
  }),
);

const response = await fetch(new URL(PATH, baseUrl), {
  method: "POST",
  headers: {
    "content-type": "application/json",
    [HEADER_TIMESTAMP]: timestamp,
    [HEADER_NONCE]: nonce,
    [HEADER_SIGNATURE]: signature,
    [HEADER_KEY_ID]: keyId,
  },
  body,
});

console.log(`status=${response.status}`);
if (response.status !== 200) {
  console.log("FAIL  probe denied or unavailable (no request details printed)");
  process.exit(1);
}
const report = (await response.json()) as {
  ok?: unknown;
  network?: unknown;
  broadcast?: unknown;
  checkCount?: unknown;
  passedCount?: unknown;
  checks?: Record<string, unknown>;
};
console.log(
  `ok=${report.ok === true} network=${String(report.network)} broadcast=${String(report.broadcast)} ` +
    `checks=${String(report.passedCount)}/${String(report.checkCount)}`,
);
for (const [name, value] of Object.entries(report.checks ?? {})) {
  console.log(`${value === true ? "PASS" : "FAIL"}  ${name}`);
}
if (report.ok !== true || report.checkCount !== report.passedCount) process.exit(1);
