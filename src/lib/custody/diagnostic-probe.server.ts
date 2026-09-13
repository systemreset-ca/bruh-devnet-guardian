/**
 * Deliberate reintroduction of the authenticated runtime diagnostic probe.
 *
 * This exists so the deployed Worker runtime can be validated (Web Crypto,
 * AES-256-GCM envelope, SDK signing, fail-closed auth, durable nonce store)
 * BEFORE any funded integration. It was removed in an earlier slice because
 * authentication was incomplete; it now requires complete durable-nonce auth
 * plus an explicit diagnostic kill switch.
 *
 * Hard constraints enforced here:
 *  - POST only.
 *  - Body is streamed with a hard 1024-byte cap; anything larger is aborted.
 *  - Body must be exactly the empty JSON object `{}`.
 *  - No caller-supplied key material, address, wallet or transaction input.
 *  - Response carries booleans and counts only — never addresses, ciphertext,
 *    seeds, signatures or wire bytes.
 *  - No RPC, no broadcast, no funding.
 *  - Denies when the diagnostic flag, caller secret, expected key ID or durable
 *    nonce store is missing, and on stale, tampered or replayed requests.
 *  - Never logs request headers, bodies or key material.
 */
import { runEphemeralSelfCheck } from "./self-check.server";
import { unauthorizedResponse, verifySignerRequest, type NonceConsumer } from "./request-auth.server";

export const MAX_PROBE_BODY_BYTES = 1024;
export const EXPECTED_PROBE_BODY = "{}";

export interface ProbeDeps {
  /** Explicit kill switch. Anything other than the literal "true" disables. */
  diagnosticEnabled: string | undefined;
  secret: string | undefined;
  expectedKeyId: string | undefined;
  consumeNonce: NonceConsumer | undefined | null;
  now?: number;
}

function notFoundResponse(): Response {
  // Disabled diagnostic is indistinguishable from a route that does not exist.
  return new Response(JSON.stringify({ error: "not_found" }), {
    status: 404,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

/** Streamed read with a hard byte cap; returns null when the cap is exceeded. */
export async function readCappedBody(request: Request, maxBytes: number): Promise<string | null> {
  const body = request.body;
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(joined);
}

export async function handleDiagnosticProbe(
  request: Request,
  deps: ProbeDeps,
): Promise<Response> {
  if (deps.diagnosticEnabled !== "true") return notFoundResponse();
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        allow: "POST",
      },
    });
  }

  const rawBody = await readCappedBody(request, MAX_PROBE_BODY_BYTES);
  if (rawBody === null) return unauthorizedResponse();
  if (rawBody !== EXPECTED_PROBE_BODY) return unauthorizedResponse();

  const url = new URL(request.url);
  const auth = await verifySignerRequest({
    method: request.method,
    path: url.pathname,
    headers: request.headers,
    rawBody,
    secret: deps.secret,
    expectedKeyId: deps.expectedKeyId,
    consumeNonce: deps.consumeNonce,
    ...(deps.now === undefined ? {} : { now: deps.now }),
  });
  if (!auth.ok) return unauthorizedResponse();

  const report = await runEphemeralSelfCheck();
  const checkEntries = Object.entries(report.checks);
  // Booleans and counts only.
  const body = {
    ok: report.ok === true,
    runtime: "server" as const,
    network: "devnet" as const,
    broadcast: false as const,
    checkCount: checkEntries.length,
    passedCount: checkEntries.filter(([, value]) => value === true).length,
    checks: Object.fromEntries(checkEntries.map(([name, value]) => [name, value === true])),
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
