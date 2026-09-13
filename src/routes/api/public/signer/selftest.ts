/**
 * Server-runtime diagnostic probe. Authenticated, fail-closed, side-effect free.
 *
 * It exercises ephemeral AES-256-GCM envelope + keypair + constrained SOL
 * transfer signing entirely in memory and returns only booleans and counts.
 * It accepts no caller key material, provisions nothing durable, signs nothing
 * the caller supplies, touches no RPC and broadcasts nothing.
 *
 * Without SIGNER_CALLER_SECRET in the server environment every request is
 * rejected with an opaque 401. There is no default or demo secret.
 */
import { createFileRoute } from "@tanstack/react-router";

const PATH = "/api/public/signer/selftest";

export const Route = createFileRoute("/api/public/signer/selftest")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { verifySignerRequest, unauthorizedResponse } = await import(
          "@/lib/custody/request-auth.server"
        );

        const { getDurableNonceConsumer } = await import("@/lib/custody/nonce-store.server");

        const rawBody = await request.text();
        const auth = await verifySignerRequest({
          method: "POST",
          path: PATH,
          headers: request.headers,
          rawBody,
          // Read per-request: env is injected at call time in the server runtime.
          secret: process.env["SIGNER_CALLER_SECRET"],
          expectedKeyId: process.env["SIGNER_CALLER_KEY_ID"],
          // No durable atomic nonce store is deployed yet, so this resolves to
          // null and every request fails closed. There is no in-memory fallback.
          consumeNonce: await getDurableNonceConsumer(),
        });
        if (!auth.ok) return unauthorizedResponse();

        const { runEphemeralSelfCheck } = await import("@/lib/custody/self-check.server");
        const report = await runEphemeralSelfCheck();

        return new Response(JSON.stringify(report), {
          status: report.ok ? 200 : 500,
          headers: { "content-type": "application/json", "cache-control": "no-store" },
        });
      },
    },
  },
});
