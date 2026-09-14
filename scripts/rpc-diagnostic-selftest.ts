/**
 * CLI self-check for the authenticated READ-ONLY RPC diagnostic handler.
 *
 * Runs the handler in-process with a TEST-ONLY in-memory nonce store, throwaway
 * generated caller credentials and a mock RPC transport. This proves guard logic
 * and response hygiene only; it is NOT evidence about the deployed Worker
 * runtime and NOT proof of real provider behaviour.
 *
 * Output is booleans and counts only. No secret, header set, body, address or
 * key material is printed.
 */
import { randomBytes } from "node:crypto";

import { MAX_PROBE_BODY_BYTES } from "../src/lib/custody/diagnostic-probe.server";
import { handleRpcDiagnosticProbe } from "../src/lib/custody/rpc-diagnostic.server";
import {
  devnetRpcEnvFromProcess,
  resolveDevnetRpcEndpoint,
} from "../src/lib/custody/rpc-endpoint.server";
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
import { DEVNET_GENESIS } from "../src/lib/custody/sol-transfer.server";
import {
  createFailingNonceStore,
  createInMemoryNonceStore,
} from "./support/in-memory-nonce-store";

// Throwaway configuration for this offline suite only: not a real provider key.
process.env["BRUH_DEVNET_API_KEY"] = "throwaway-selftest-key-0002";
delete process.env["SOLANA_RPC_URL"];
const DIAGNOSTIC_RPC_ENDPOINT = resolveDevnetRpcEndpoint(devnetRpcEnvFromProcess());

let passed = 0;
let failed = 0;
function check(name: string, ok: boolean): void {
  if (ok) passed += 1;
  else failed += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
}

const SECRET = randomBytes(48).toString("hex");
const KEY_ID = "rpc-probe-test-key";
const PATH = "/api/public/signer/rpc-selftest";
const URL_STR = `https://example.invalid${PATH}`;
const BLOCKHASH = "9AeH2ZmSPtWjfMDDwbF7hE7fUFyHNn9zA9Xurn8gvA7g";

const requestedMethods: string[] = [];
const requestedEndpoints: string[] = [];
const mockTransport: typeof fetch = async (input, init) => {
  requestedEndpoints.push(String(input));
  const body = JSON.parse(String(init?.body)) as { id: number; method: string };
  requestedMethods.push(body.method);
  const result =
    body.method === "getGenesisHash"
      ? DEVNET_GENESIS
      : body.method === "getLatestBlockhash"
        ? { value: { blockhash: BLOCKHASH, lastValidBlockHeight: 300_000_000 } }
        : { value: 5000 };
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), { status: 200 });
};

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
  transport: mockTransport,
});

async function respond(request: Request, deps: Record<string, unknown>): Promise<Response> {
  return handleRpcDiagnosticProbe(request, deps as never);
}
async function statusOf(request: Request, deps: Record<string, unknown>): Promise<number> {
  return (await respond(request, deps)).status;
}

console.log("--- kill switch ---");
check("missing diagnostic flag denies (404)", (await statusOf(signedRequest(), { ...enabledDeps(), diagnosticEnabled: undefined })) === 404);
check('flag value other than "true" denies (404)', (await statusOf(signedRequest(), { ...enabledDeps(), diagnosticEnabled: "TRUE" })) === 404);
check("disabled flag makes no RPC call at all", (() => {
  const before = requestedMethods.length;
  return before === 0;
})());

console.log("\n--- method and payload shape ---");
for (const method of ["GET", "PUT", "DELETE", "PATCH"]) {
  check(`${method} denied (405, POST only)`, (await statusOf(signedRequest({ method }), enabledDeps())) === 405);
}
check("non-empty JSON payload denied", (await statusOf(signedRequest({ body: '{"endpoint":"https://evil.invalid"}' }), enabledDeps())) === 401);
check("client-chosen commitment param denied", (await statusOf(signedRequest({ body: '{"commitment":"processed"}' }), enabledDeps())) === 401);
check("empty string payload denied", (await statusOf(signedRequest({ body: "" }), enabledDeps())) === 401);
check(
  `payload over ${MAX_PROBE_BODY_BYTES} bytes denied`,
  (await statusOf(signedRequest({ body: `{"pad":"${"a".repeat(MAX_PROBE_BODY_BYTES + 64)}"}` }), enabledDeps())) === 401,
);

console.log("\n--- configuration must be complete ---");
check("missing caller secret denies", (await statusOf(signedRequest(), { ...enabledDeps(), secret: undefined })) === 401);
check("short caller secret denies", (await statusOf(signedRequest(), { ...enabledDeps(), secret: "too-short" })) === 401);
check("missing expected key id denies", (await statusOf(signedRequest(), { ...enabledDeps(), expectedKeyId: undefined })) === 401);
check("missing nonce store denies", (await statusOf(signedRequest(), { ...enabledDeps(), consumeNonce: null })) === 401);
check("failing nonce store denies", (await statusOf(signedRequest(), { ...enabledDeps(), consumeNonce: createFailingNonceStore().consume })) === 401);

console.log("\n--- authentication ---");
check("unsigned request denies", (await statusOf(new Request(URL_STR, { method: "POST", body: "{}" }), enabledDeps())) === 401);
for (const header of [HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE, HEADER_KEY_ID]) {
  check(`missing ${header} denies`, (await statusOf(signedRequest({ omitHeader: header }), enabledDeps())) === 401);
}
check("wrong caller secret denies", (await statusOf(signedRequest({ secret: randomBytes(48).toString("hex") }), enabledDeps())) === 401);
check("substituted key id denies", (await statusOf(signedRequest({ keyId: "other-key" }), enabledDeps())) === 401);
check("key id not bound into the signature denies", (await statusOf(signedRequest({ signWithKeyId: "other-key" }), enabledDeps())) === 401);
check("signature over another path denies", (await statusOf(signedRequest({ signedPath: "/api/public/signer/selftest" }), enabledDeps())) === 401);
check("stale timestamp denies", (await statusOf(signedRequest({ timestamp: String(Date.now() - 600_000) }), enabledDeps())) === 401);
check("future timestamp denies", (await statusOf(signedRequest({ timestamp: String(Date.now() + 600_000) }), enabledDeps())) === 401);
check("garbage signature denies", (await statusOf(signedRequest({ signature: "ff".repeat(32) }), enabledDeps())) === 401);
{
  const deps = enabledDeps();
  const nonce = newNonce();
  const first = await statusOf(signedRequest({ nonce }), deps);
  const replayed = await statusOf(signedRequest({ nonce }), deps);
  check("valid signed request is served once", first === 200);
  check("byte-identical replay denies", replayed === 401);
}

console.log("\n--- denial responses leak nothing ---");
{
  const denied = await respond(signedRequest({ secret: randomBytes(48).toString("hex") }), enabledDeps());
  const text = await denied.text();
  check("denial body is uniform and opaque", text === JSON.stringify({ error: "unauthorized" }));
  check("denial is not cached", denied.headers.get("cache-control") === "no-store");
  const notFound = await respond(signedRequest(), { ...enabledDeps(), diagnosticEnabled: "false" });
  check("disabled body is a plain not_found", (await notFound.text()) === JSON.stringify({ error: "not_found" }));
}

console.log("\n--- served report hygiene ---");
{
  requestedMethods.length = 0;
  requestedEndpoints.length = 0;
  const response = await respond(signedRequest(), enabledDeps());
  const text = await response.text();
  const report = JSON.parse(text) as Record<string, unknown>;
  check("authenticated probe serves 200", response.status === 200);
  check("report is not cached", response.headers.get("cache-control") === "no-store");
  check("report says ok", report["ok"] === true);
  check("report says devnet, read-only, no broadcast", report["network"] === "devnet" && report["readOnly"] === true && report["broadcast"] === false);
  check("report counts three RPC reads", report["rpcCallCount"] === 3);
  check("report passed every check", report["passedCount"] === report["checkCount"]);
  check("report values are booleans only", Object.values(report["checks"] as Record<string, unknown>).every((v) => typeof v === "boolean"));
  check("report contains no blockhash", !text.includes(BLOCKHASH));
  check("report contains no address-shaped string", !/[1-9A-HJ-NP-Za-km-z]{32,}/.test(text));
  check("report contains no base64 wire blob", !/[A-Za-z0-9+/]{64,}={0,2}/.test(text));
  check("report mentions no provider host", !text.includes("solana.com"));
  check("endpoint is the pinned server-owned devnet endpoint", requestedEndpoints.every((e) => e === DIAGNOSTIC_RPC_ENDPOINT));
  check("only read methods were requested", requestedMethods.join(",") === "getGenesisHash,getLatestBlockhash,getFeeForMessage");
  check("no sendTransaction, no airdrop", !requestedMethods.some((m) => m === "sendTransaction" || m === "requestAirdrop"));
}
{
  const dead: typeof fetch = async () => new Response("", { status: 503 });
  const response = await respond(signedRequest(), { ...enabledDeps(), transport: dead });
  const text = await response.text();
  check("provider outage reports ok=false, not an error page", response.status === 200 && JSON.parse(text)["ok"] === false);
  check("provider outage surfaces no provider text", !text.includes("solana.com") && !/[a-z]{4,}\s[a-z]{4,}/i.test(JSON.stringify(JSON.parse(text)["transport"])));
  const meta = JSON.parse(text)["transport"] as Record<string, unknown>;
  check("provider outage reports the numeric status only", Array.isArray(meta["statuses"]) && (meta["statuses"] as unknown[]).every((s) => typeof s === "number") && (meta["statuses"] as number[])[0] === 503);
  check("provider outage classifies as http_error", meta["classification"] === "http_error" && meta["timedOut"] === false && meta["transportFailed"] === false);
}

console.log(`\n${passed} passed, ${failed} failed`);
console.log(
  "NOTE: guard logic and hygiene only, with a mock transport. NOT deployed-Worker RPC proof. The live diagnostic stays disabled until reviewed and published.",
);
if (failed > 0) process.exit(1);
