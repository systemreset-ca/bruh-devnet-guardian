/**
 * Durable nonce store adapter for signer request authentication.
 *
 * Replay protection is enforced by a single atomic database call:
 * `public.consume_signer_nonce(key_id, nonce, ttl_seconds)`, a SECURITY DEFINER
 * routine that performs an INSERT ... ON CONFLICT first-use claim on
 * `public.signer_nonces`. The table grants no privileges to any Data API role
 * and has row level security with deny-all policies, so the routine is the only
 * access path.
 *
 * There is deliberately NO in-memory fallback: a process-local Map cannot stop
 * replay across Worker instances or restarts. If the store is unreachable or
 * misconfigured, this resolves to `null` or throws, and the verifier rejects
 * with `nonce_store_unavailable` (fail closed).
 *
 * Test-only in-memory stores live in the test harness under scripts/, never
 * here.
 */
import type { NonceConsumer } from "./request-auth.server";

/** Hard TTL bounds, mirrored by the database routine. */
const MIN_TTL_SECONDS = 1;
const MAX_TTL_SECONDS = 300;

/**
 * Returns an atomic durable nonce consumer, or `null` when the backend is not
 * configured. `null` makes the verifier reject with `nonce_store_unavailable`.
 */
export async function getDurableNonceConsumer(): Promise<NonceConsumer | null> {
  const url = process.env["SUPABASE_URL"];
  const serviceKey = process.env["SUPABASE_SERVICE_ROLE_KEY"];
  if (!url || !serviceKey) return null;

  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

  return async ({ keyId, nonce, now, expiresAt }) => {
    // Derive the TTL from the verifier's own window; never from a caller value.
    const ttlSeconds = Math.ceil((expiresAt - now) / 1000);
    if (
      !Number.isFinite(ttlSeconds) ||
      ttlSeconds < MIN_TTL_SECONDS ||
      ttlSeconds > MAX_TTL_SECONDS
    ) {
      // Fail closed rather than clamping to a longer-lived record.
      throw new Error("nonce_ttl_out_of_range");
    }

    const { data, error } = await supabaseAdmin.rpc("consume_signer_nonce", {
      p_key_id: keyId,
      p_nonce: nonce,
      p_ttl_seconds: ttlSeconds,
    });

    // Never log or surface the error body: it can echo request-derived values.
    if (error) throw new Error("nonce_store_error");
    if (typeof data !== "boolean") throw new Error("nonce_store_error");

    return data;
  };
}
