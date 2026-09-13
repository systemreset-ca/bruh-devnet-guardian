/**
 * Authenticated read-only RPC diagnostic probe — POST only.
 *
 * Same durable HMAC auth, kill switch and uniform denials as the crypto
 * diagnostic. Three devnet reads only (genesis, finalized blockhash, message
 * fee) against a server-pinned endpoint in source. No caller endpoint or client
 * params, no wallet or address input, no funding, no broadcast. Returns
 * booleans and counts only. Nothing about the request is logged.
 *
 * Stays disabled until reviewed and published by the reviewer:
 *   SIGNER_DIAGNOSTIC_ENABLED  must be exactly "true" to serve at all
 *   SIGNER_CALLER_SECRET       HMAC secret for the diagnostic caller
 *   SIGNER_CALLER_KEY_ID       expected key ID, bound into the canonical string
 */
import { createFileRoute } from "@tanstack/react-router";

import { getDurableNonceConsumer } from "@/lib/custody/nonce-store.server";
import { handleRpcDiagnosticProbe } from "@/lib/custody/rpc-diagnostic.server";

export const Route = createFileRoute("/api/public/signer/rpc-selftest")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        let consumeNonce = null;
        try {
          consumeNonce = await getDurableNonceConsumer();
        } catch {
          consumeNonce = null; // fail closed inside the verifier
        }
        return handleRpcDiagnosticProbe(request, {
          diagnosticEnabled: process.env["SIGNER_DIAGNOSTIC_ENABLED"],
          secret: process.env["SIGNER_CALLER_SECRET"],
          expectedKeyId: process.env["SIGNER_CALLER_KEY_ID"],
          consumeNonce,
        });
      },
    },
  },
});
