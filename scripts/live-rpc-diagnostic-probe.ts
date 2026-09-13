/**
 * Trusted live probe for the READ-ONLY RPC diagnostic on the DEPLOYED runtime.
 *
 * Reads the already-injected diagnostic caller credentials from the environment
 * (SIGNER_CALLER_SECRET, SIGNER_CALLER_KEY_ID) and signs one POST with an empty
 * JSON body. It NEVER prints or logs the secret, key ID, signature, nonce,
 * timestamp, any request header, the request body or any provider text — only
 * the HTTP status and the returned booleans/counts.
 *
 * It also runs two negative live checks: an unauthenticated POST must be denied,
 * and a byte-identical replay of the signed request must be denied by the
 * durable one-time-token store.
 *
 * Exactly three requests are sent (unauthenticated, signed, replay). There is no
 * polling loop: a secret change requires a republish to take effect live.
 *
 * No funding, no airdrop, no sendTransaction, no broadcast, no mainnet, no
 * wallet key is involved at any point.
 *
 * Usage: BASE_URL=https://<host> bun run scripts/live-rpc-diagnostic-probe.ts
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

const PATH = "/api/public/signer/rpc-selftest";
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

const url = new URL(PATH, baseUrl);
const body = "{}";

function signedHeaders(): Headers {
  const timestamp = String(Date.now());
  const nonce = newNonce();
  const signature = signCanonical(
    secret as string,
    canonicalString({
      keyId: keyId as string,
      method: "POST",
      path: PATH,
      timestamp,
      nonce,
      bodyDigestHex: bodyDigestHex(body),
    }),
  );
  return new Headers({
    "content-type": "application/json",
    [HEADER_TIMESTAMP]: timestamp,
    [HEADER_NONCE]: nonce,
    [HEADER_SIGNATURE]: signature,
    [HEADER_KEY_ID]: keyId as string,
  });
}

let failures = 0;
function check(name: string, ok: boolean): void {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
}

// 1. Unauthenticated live request must be denied.
const anonymous = await fetch(url, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body,
});
console.log(`unauthenticated_status=${anonymous.status}`);
check("unauthenticated live POST is denied", anonymous.status === 401 || anonymous.status === 404);
if (anonymous.status === 404) {
  console.log("NOTE  the diagnostic is disabled on this deployment; no read was attempted");
  process.exit(failures > 0 ? 1 : 0);
}

// 2. One signed request. Headers are reused verbatim for the replay check.
const headers = signedHeaders();
const signed = await fetch(url, { method: "POST", headers, body });
console.log(`signed_status=${signed.status}`);
check("signed live request is served", signed.status === 200);
if (signed.status !== 200) {
  console.log("FAIL  denied or unavailable (no request details printed)");
  process.exit(1);
}

const report = (await signed.json()) as {
  ok?: unknown;
  network?: unknown;
  readOnly?: unknown;
  broadcast?: unknown;
  rpcCallCount?: unknown;
  checkCount?: unknown;
  passedCount?: unknown;
  checks?: Record<string, unknown>;
  transport?: {
    attemptCount?: unknown;
    responseCount?: unknown;
    statuses?: unknown;
    httpErrorCount?: unknown;
    timedOut?: unknown;
    transportFailed?: unknown;
    classification?: unknown;
  };
};
console.log(
  `ok=${report.ok === true} network=${String(report.network)} readOnly=${String(report.readOnly)} ` +
    `broadcast=${String(report.broadcast)} rpcCalls=${String(report.rpcCallCount)} ` +
    `checks=${String(report.passedCount)}/${String(report.checkCount)}`,
);
// Bounded transport metadata: numeric statuses and failure-class booleans only.
const meta = report.transport ?? {};
console.log(
  `transport classification=${String(meta.classification)} attempts=${String(meta.attemptCount)} ` +
    `responses=${String(meta.responseCount)} statuses=${JSON.stringify(meta.statuses ?? [])} ` +
    `httpErrors=${String(meta.httpErrorCount)} timedOut=${String(meta.timedOut)} ` +
    `transportFailed=${String(meta.transportFailed)}`,
);
for (const [name, value] of Object.entries(report.checks ?? {})) {
  check(name, value === true);
}
check("network is devnet", report.network === "devnet");
check("no broadcast attempted", report.broadcast === false);
check("exactly three RPC reads", report.rpcCallCount === 3);
check("every check passed", report.ok === true && report.passedCount === report.checkCount);

// 3. Byte-identical replay must be denied by the durable one-time-token store.
const replay = await fetch(url, { method: "POST", headers, body });
console.log(`replay_status=${replay.status}`);
check("byte-identical replay is denied on the deployed runtime", replay.status === 401);

console.log(
  "NOTE  ephemeralInputSeedsCleared means the seed buffers this module allocated were overwritten; JavaScript and the wallet SDK cannot guarantee that all key material is erased from memory.",
);
if (failures > 0) process.exit(1);
