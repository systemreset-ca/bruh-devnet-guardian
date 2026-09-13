/**
 * Authenticated runtime diagnostic probe — POST only.
 *
 * Deliberately reintroduced so the deployed Worker runtime can be validated
 * before any funded integration. Every guard lives in
 * `@/lib/custody/diagnostic-probe.server`; this file only reads per-request
 * server environment values and resolves the durable nonce consumer.
 *
 * Denies (uniform 401) without a valid signed request; returns 404 when the
 * diagnostic kill switch is not explicitly enabled. No caller key, wallet or
 * transaction input is accepted. No RPC, broadcast or funding. Nothing about
 * the request is logged.
 *
 * Required server environment values (names only, values never in source):
 *   SIGNER_DIAGNOSTIC_ENABLED  must be exactly "true" to serve at all
 *   SIGNER_CALLER_SECRET       HMAC secret for the diagnostic caller
 *   SIGNER_CALLER_KEY_ID       expected key ID, bound into the canonical string
 */
import { createFileRoute } from "@tanstack/react-router";

import { handleDiagnosticProbe } from "@/lib/custody/diagnostic-probe.server";
import { getDurableNonceConsumer } from "@/lib/custody/nonce-store.server";

export const Route = createFileRoute("/api/public/signer/selftest")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        let consumeNonce = null;
        try {
          consumeNonce = await getDurableNonceConsumer();
        } catch {
          consumeNonce = null; // fail closed inside the verifier
        }
        return handleDiagnosticProbe(request, {
          diagnosticEnabled: process.env["SIGNER_DIAGNOSTIC_ENABLED"],
          secret: process.env["SIGNER_CALLER_SECRET"],
          expectedKeyId: process.env["SIGNER_CALLER_KEY_ID"],
          consumeNonce,
        });
      },
    },
  },
});
