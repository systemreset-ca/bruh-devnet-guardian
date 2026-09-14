/**
 * Authenticated read-only RPC diagnostic — same durable fail-closed auth as the
 * crypto diagnostic probe, same kill switch, same uniform denials.
 *
 * Accepts no caller input beyond an exactly empty JSON body: no endpoint, no
 * client params, no wallet, no address, no transaction. Returns booleans and
 * counts only. Never broadcasts, funds or airdrops. Nothing is logged.
 */
import {
  EXPECTED_PROBE_BODY,
  MAX_PROBE_BODY_BYTES,
  readCappedBody,
} from "./diagnostic-probe.server";
import { unauthorizedResponse, verifySignerRequest, type NonceConsumer } from "./request-auth.server";
import { runReadOnlyRpcSelfCheck } from "./rpc-self-check.server";
import type { DevnetRpcEnv } from "./rpc-endpoint.server";

export interface RpcProbeDeps {
  /** Explicit kill switch. Anything other than the literal "true" disables. */
  diagnosticEnabled: string | undefined;
  secret: string | undefined;
  expectedKeyId: string | undefined;
  consumeNonce: NonceConsumer | undefined | null;
  now?: number;
  /** Injected only by tests; production uses global fetch. */
  transport?: typeof fetch;
  /** Injected only by tests; production reads the server environment. */
  rpcEnv?: DevnetRpcEnv;
}

const json = (body: unknown, status: number, extra: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extra },
  });

export async function handleRpcDiagnosticProbe(
  request: Request,
  deps: RpcProbeDeps,
): Promise<Response> {
  // Disabled diagnostic is indistinguishable from a route that does not exist.
  if (deps.diagnosticEnabled !== "true") return json({ error: "not_found" }, 404);
  if (request.method !== "POST") {
    return json({ error: "method_not_allowed" }, 405, { allow: "POST" });
  }

  const rawBody = await readCappedBody(request, MAX_PROBE_BODY_BYTES);
  if (rawBody === null || rawBody !== EXPECTED_PROBE_BODY) return unauthorizedResponse();

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

  const report = await runReadOnlyRpcSelfCheck(
    deps.transport ?? ((input, init) => globalThis.fetch(input, init)),
    ...(deps.rpcEnv === undefined ? [] : [deps.rpcEnv]),
  );
  return json(
    {
      ok: report.ok,
      runtime: "server" as const,
      network: report.network,
      broadcast: report.broadcast,
      readOnly: true as const,
      rpcCallCount: report.rpcCallCount,
      checkCount: report.checkCount,
      passedCount: report.passedCount,
      checks: report.checks,
      // Bounded transport metadata: numeric statuses and failure-class booleans
      // only. No body, headers, endpoint, key or provider error text.
      transport: report.transport,
      // Presence and devnet-compatibility booleans only: never a key, URL or host.
      config: report.config,
    },
    200,
  );
}
