/**
 * Isolated signer bridge route — POST /api/internal/custody/provision.
 *
 * DEFAULT DISABLED. `BRUH_BRIDGE_ENABLED` must be exactly "true" to serve at
 * all; anything else returns 404 (indistinguishable from a missing route).
 *
 * Fails closed, with no fallback, when any of these is absent:
 *   BRUH_BRIDGE_CALLER_KEY_ID      expected calling backend key ID
 *   BRUH_BRIDGE_CALLER_PUBLIC_KEY  pinned BRUH Ed25519 PUBLIC verification key
 *                                  (64 hex chars). Only a public key is ever
 *                                  exchanged — never a shared, elevated or
 *                                  diagnostic caller secret.
 *   the durable nonce store, the production wrapping key, the wallet store
 *
 * Telegram verification uses the pinned production Ed25519 verifier (real bot
 * ID and Telegram production public key). Nothing about the request is logged.
 * No wallet schema is applied, no funding, no signing, no mainnet.
 */
import { createFileRoute } from "@tanstack/react-router";

import { getDurableNonceConsumer } from "@/lib/custody/nonce-store.server";
import { verifyThirdPartyInitData } from "@/lib/telegram/init-data.server";
import { receiveProvisionBridge } from "@/lib/wallets/bridge-receiver.server";
import { provisionVerifiedScope } from "@/lib/wallets/provisioning.server";
import { getDurableWalletStore } from "@/lib/wallets/wallet-store.server";
import { getProductionWrappingVault } from "@/lib/wallets/wrapping-key.server";

export const Route = createFileRoute("/api/internal/custody/provision")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        let consumeNonce = null;
        try {
          consumeNonce = await getDurableNonceConsumer();
        } catch {
          consumeNonce = null; // fail closed inside the verifier
        }

        return receiveProvisionBridge(request, {
          enabled: process.env["BRUH_BRIDGE_ENABLED"] === "true",
          expectedKeyId: process.env["BRUH_BRIDGE_CALLER_KEY_ID"],
          expectedPublicKey: process.env["BRUH_BRIDGE_CALLER_PUBLIC_KEY"],
          consumeNonce,
          verifyTelegram: (raw, now) => {
            const result = verifyThirdPartyInitData(raw, { nowMs: now });
            return result.ok ? result.telegramUserId : null;
          },
          provision: async (scope) => {
            const [vault, store] = await Promise.all([
              getProductionWrappingVault().catch(() => null),
              getDurableWalletStore().catch(() => null),
            ]);
            const outcome = await provisionVerifiedScope({ scope, vault, store });
            // A denial must never become a 200: the receiver refuses any result
            // that is not the exact frozen devnet public metadata shape.
            if (!outcome.ok) throw new Error("provisioning_unavailable");
            return { created: outcome.created, wallet: outcome.wallet };
          },
        });
      },
    },
  },
});
