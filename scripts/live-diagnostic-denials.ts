/**
 * Trusted live denial checks against the DEPLOYED Worker runtime.
 *
 * 1. Unauthenticated POST (no auth headers) must be denied.
 * 2. One valid signed request must be accepted, and the SAME signed request
 *    replayed byte-for-byte must be denied by the durable nonce store.
 *
 * Prints only HTTP statuses and booleans. Never prints the caller secret, key
 * ID, signature, nonce, headers or body.
 *
 * Usage: BASE_URL=https://<host> bun run scripts/live-diagnostic-denials.ts
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

if (!baseUrl || !secret || !keyId) {
  console.log("FAIL  base URL or caller credentials not available in this environment");
  process.exit(1);
}

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean, note = "") {
  if (ok) pass += 1;
  else fail += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${note ? `  (${note})` : ""}`);
}

const url = new URL(PATH, baseUrl);
const body = "{}";

// 1. Unauthenticated request.
const unauth = await fetch(url, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body,
});
check("deployed_unauthenticated_post_denied", unauth.status === 401, `status=${unauth.status}`);

// 2. One signed request, then the identical request replayed.
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
const headers = {
  "content-type": "application/json",
  [HEADER_TIMESTAMP]: timestamp,
  [HEADER_NONCE]: nonce,
  [HEADER_SIGNATURE]: signature,
  [HEADER_KEY_ID]: keyId,
};

const first = await fetch(url, { method: "POST", headers, body });
check("deployed_signed_request_accepted", first.status === 200, `status=${first.status}`);

const replay = await fetch(url, { method: "POST", headers, body });
check("deployed_identical_replay_denied", replay.status === 401, `status=${replay.status}`);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
