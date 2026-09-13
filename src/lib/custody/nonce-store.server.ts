/**
 * Durable nonce store resolution for signer request authentication.
 *
 * A process-local Map cannot prevent replay across Worker instances or
 * restarts, so this module deliberately provides NO in-memory implementation.
 * Until a durable atomic store is deployed (conditional insert on a unique
 * nonce key, shared by every instance), this resolves to `null` and every
 * authenticated request fails closed.
 *
 * Test-only in-memory stores live in the test harness under scripts/, never
 * here.
 */
import type { NonceConsumer } from "./request-auth.server";

/**
 * Returns an atomic durable nonce consumer, or `null` when none is configured.
 * `null` makes the verifier reject with `nonce_store_unavailable`.
 */
export async function getDurableNonceConsumer(): Promise<NonceConsumer | null> {
  // Not deployed yet: no durable table, no schema, no fallback.
  return null;
}
