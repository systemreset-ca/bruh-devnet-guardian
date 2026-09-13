/**
 * CLI self-check for the authenticated runtime diagnostic probe handler.
 *
 * Runs the handler in-process with a TEST-ONLY in-memory nonce store and
 * throwaway generated caller credentials. This proves the guard logic only; it
 * is NOT evidence about the deployed Worker runtime (that requires the live
 * probe after publish).
 *
 * Output is booleans and counts only. No secret, header set, body or key
 * material is printed.
 */
import { randomBytes } from "node:crypto";

import {
  handleDiagnosticProbe,
  MAX_PROBE_BODY_BYTES,
} from "../src/lib/custody/diagnostic-probe.server";
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
import {
  createFailingNonceStore,
  createInMemoryNonceStore,
} from "./support/in-memory-nonce-store";

let passed = 0;
let failed = 0;
function check(name: string, ok: boolean): void {
  if (ok) passed += 1;
  else failed += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
}

// Throwaway credentials for this process only — never printed, never persisted.
const SECRET = randomBytes(48).toString("hex");
const KEY_ID = "probe-test-key";
const PATH = "/api/public/signer/selftest";
const URL_STR = `https://example.invalid${PATH}`;

function signedRequest(opts?: {
  body?: string;
  method?: string;
  nonce?: string;
  timestamp?: string;
  keyId?: string;
  signWithKeyId?: string;
  secret?: string;
  signedPath?: string;
  omitHeader?: string;
  signature?: string;
}): Request {
  const method = opts?.method ?? "POST";
  const body = opts?.body ?? "{}";
  const timestamp = opts?.timestamp ?? String(Date.now());
  const nonce = opts?.nonce ?? newNonce();
  const keyId = opts?.keyId ?? KEY_ID;
  const signature =
    opts?.signature ??
    signCanonical(
      opts?.secret ?? SECRET,
      canonicalString({
        keyId: opts?.signWithKeyId ?? keyId,
        method,
        path: opts?.signedPath ?? PATH,
        timestamp,
        nonce,
        bodyDigestHex: bodyDigestHex(body),
      }),
    );
  const headers = new Headers({
    "content-type": "application/json",
    [HEADER_TIMESTAMP]: timestamp,
    [HEADER_NONCE]: nonce,
    [HEADER_SIGNATURE]: signature,
    [HEADER_KEY_ID]: keyId,
  });
  if (opts?.omitHeader) headers.delete(opts.omitHeader);
  return new Request(URL_STR, { method, headers, body: method === "GET" ? null : body });
}

const enabledDeps = () => ({
  diagnosticEnabled: "true",
  secret: SECRET,
  expectedKeyId: KEY_ID,
  consumeNonce: createInMemoryNonceStore().consume,
});

async function statusOf(request: Request, deps: Record<string, unknown>): Promise<number> {
  // deps typing is validated by the handler signature at the call sites below.
  const response = await handleDiagnosticProbe(request, deps as never);
  return response.status;
}

console.log("--- kill switch ---");
check(
  "missing diagnostic flag denies (404)",
  (await statusOf(signedRequest(), { ...enabledDeps(), diagnosticEnabled: undefined })) === 404,
);
check(
  "flag value other than \"true\" denies (404)",
  (await statusOf(signedRequest(), { ...enabledDeps(), diagnosticEnabled: "1" })) === 404,
);

console.log("\n--- method and payload shape ---");
check(
  "GET denied (405, POST only)",
  (await statusOf(signedRequest({ method: "GET" }), enabledDeps())) === 405,
);
check(
  "non-empty JSON payload denied",
  (await statusOf(signedRequest({ body: '{"a":1}' }), enabledDeps())) === 401,
);
check(
  "empty string payload denied",
  (await statusOf(signedRequest({ body: "" }), enabledDeps())) === 401,
);
check(
  `payload over ${MAX_PROBE_BODY_BYTES} bytes denied`,
  (await statusOf(
    signedRequest({ body: `{"pad":"${"a".repeat(MAX_PROBE_BODY_BYTES + 64)}"}` }),
    enabledDeps(),
  )) === 401,
);

console.log("\n--- configuration must be complete ---");
check(
  "missing caller secret denies",
  (await statusOf(signedRequest(), { ...enabledDeps(), secret: undefined })) === 401,
);
check(
  "short caller secret denies",
  (await statusOf(signedRequest(), { ...enabledDeps(), secret: "too-short" })) === 401,
);
check(
  "missing expected key ID denies",
  (await statusOf(signedRequest(), { ...enabledDeps(), expectedKeyId: undefined })) === 401,
);
check(
  "missing durable nonce store denies",
  (await statusOf(signedRequest(), { ...enabledDeps(), consumeNonce: null })) === 401,
);
check(
  "nonce store outage denies",
  (await statusOf(signedRequest(), { ...enabledDeps(), consumeNonce: createFailingNonceStore() })) ===
    401,
);

console.log("\n--- authentication ---");
check(
  "wrong caller secret denies",
  (await statusOf(signedRequest({ secret: randomBytes(48).toString("hex") }), enabledDeps())) ===
    401,
);
check(
  "substituted caller key ID denies",
  (await statusOf(signedRequest({ keyId: "someone-else" }), enabledDeps())) === 401,
);
check(
  "signature bound to another key ID denies",
  (await statusOf(signedRequest({ signWithKeyId: "other-key" }), enabledDeps())) === 401,
);
check(
  "signature bound to another path denies",
  (await statusOf(signedRequest({ signedPath: "/api/public/signer/other" }), enabledDeps())) === 401,
);
check(
  "stale timestamp denies",
  (await statusOf(signedRequest({ timestamp: String(Date.now() - 120_000) }), enabledDeps())) === 401,
);
check(
  "future timestamp denies",
  (await statusOf(signedRequest({ timestamp: String(Date.now() + 120_000) }), enabledDeps())) === 401,
);
check(
  "malformed signature denies",
  (await statusOf(signedRequest({ signature: "zz" }), enabledDeps())) === 401,
);
check(
  "missing signature header denies",
  (await statusOf(signedRequest({ omitHeader: HEADER_SIGNATURE }), enabledDeps())) === 401,
);
check(
  "missing nonce header denies",
  (await statusOf(signedRequest({ omitHeader: HEADER_NONCE }), enabledDeps())) === 401,
);

console.log("\n--- accepted request and replay ---");
const store = createInMemoryNonceStore();
const deps = { ...enabledDeps(), consumeNonce: store.consume };
const nonce = newNonce();
const first = await handleDiagnosticProbe(signedRequest({ nonce }), deps as never);
const firstBody = (await first.json()) as Record<string, unknown>;
check("valid signed request accepted (200)", first.status === 200);
check("report ok is true", firstBody["ok"] === true);
check("report declares devnet and no broadcast", firstBody["network"] === "devnet" && firstBody["broadcast"] === false);
check(
  "every reported check passed",
  typeof firstBody["checkCount"] === "number" &&
    (firstBody["checkCount"] as number) > 0 &&
    firstBody["checkCount"] === firstBody["passedCount"],
);
check(
  "response carries booleans and counts only",
  (() => {
    const allowedTop = new Set([
      "ok",
      "runtime",
      "network",
      "broadcast",
      "checkCount",
      "passedCount",
      "checks",
    ]);
    if (Object.keys(firstBody).some((k) => !allowedTop.has(k))) return false;
    const checks = firstBody["checks"] as Record<string, unknown>;
    return Object.values(checks).every((v) => typeof v === "boolean");
  })(),
);
check(
  "response contains no base58/base64/hex material",
  !/[A-Za-z0-9+/=]{24,}/.test(JSON.stringify(firstBody).replace(/"[a-zA-Z]+":/g, "")),
);
check(
  "replayed nonce denied",
  (await statusOf(signedRequest({ nonce }), deps)) === 401,
);
check(
  "uniform 401 body reveals nothing",
  await (async () => {
    const denied = await handleDiagnosticProbe(signedRequest({ secret: "x".repeat(64) }), deps as never);
    const body = (await denied.json()) as Record<string, unknown>;
    return denied.status === 401 && Object.keys(body).length === 1 && body["error"] === "unauthorized";
  })(),
);

console.log(`\n${passed} passed, ${failed} failed`);
console.log(
  "NOTE: in-process guard proof only. Deployed Worker runtime execution is NOT verified by this suite.",
);
if (failed > 0) process.exit(1);
