/**
 * TEST-ONLY in-memory nonce store.
 *
 * Lives in the test harness on purpose: a process-local store cannot prevent
 * replay across Worker instances or restarts, so it must never be importable
 * from the production modules under src/lib/custody.
 *
 * The check-and-insert below runs synchronously before any await, so it is
 * atomic under the single-threaded event loop — concurrent attempts on the same
 * nonce see exactly one `true`.
 */
import type { NonceConsumer } from "../../src/lib/custody/request-auth.server";

export function createInMemoryNonceStore(): {
  consume: NonceConsumer;
  size: () => number;
} {
  const seen = new Map<string, number>();
  return {
    consume: async ({ keyId, nonce, now, expiresAt }) => {
      for (const [key, expiry] of seen) if (expiry <= now) seen.delete(key);
      const key = `${keyId}:${nonce}`;
      if (seen.has(key)) return false;
      seen.set(key, expiresAt);
      return true;
    },
    size: () => seen.size,
  };
}

/** Store that always fails, to prove the verifier fails closed on outage. */
export function createFailingNonceStore(): NonceConsumer {
  return async () => {
    throw new Error("nonce store unavailable");
  };
}
