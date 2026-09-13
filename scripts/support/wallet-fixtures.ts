/**
 * TEST HARNESS ONLY — never imported by production modules.
 *
 * Contains:
 *   - an in-memory wallet store whose insert is a synchronous check-then-set
 *     before any await, so concurrent same-scope attempts are atomic under the
 *     single-threaded event loop (exactly one creator);
 *   - a failing store, to prove fail-closed behaviour;
 *   - MOCK membership approval callbacks. These are fixtures, NOT real BRUH
 *     group/membership proof: no trusted BRUH membership source is wired up.
 *   - generated-key initData fixtures. These are NOT real Telegram signatures;
 *     the pinned production verifier rejects them by design.
 */
import { webcrypto } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import type {
  WalletRecord,
  WalletScope,
  WalletStore,
} from "../../src/lib/wallets/wallet-store.server";
import type {
  MembershipApproval,
  MembershipAuthorizer,
  MembershipDenial,
} from "../../src/lib/wallets/authorization.server";
import {
  verifyThirdPartyInitDataWithConfig,
  type InitDataResult,
} from "../../src/lib/telegram/init-data.server";

const scopeKey = (scope: WalletScope) =>
  [
    scope.groupId,
    scope.membershipId,
    scope.telegramChatId,
    scope.telegramUserId,
    scope.network,
  ].join("|");

export function createInMemoryWalletStore(): WalletStore & {
  rows: () => WalletRecord[];
  inserts: () => number;
} {
  const byScope = new Map<string, WalletRecord>();
  let attemptedInserts = 0;

  return {
    async findByScope(scope) {
      return byScope.get(scopeKey(scope)) ?? null;
    },
    async insertIfAbsent(candidate) {
      attemptedInserts += 1;
      // Synchronous claim: no await between read and write.
      const key = scopeKey(candidate.scope);
      const existing = byScope.get(key);
      if (existing) return { created: false, record: existing };
      byScope.set(key, candidate);
      return { created: true, record: candidate };
    },
    rows: () => [...byScope.values()],
    inserts: () => attemptedInserts,
  };
}

export function createFailingWalletStore(): WalletStore {
  return {
    async findByScope() {
      throw new Error("store down");
    },
    async insertIfAbsent() {
      throw new Error("store down");
    },
  };
}

/** MOCK trusted-approval callback (fixture, not real membership proof). */
export function mockAuthorizer(
  approval: Omit<MembershipApproval, "approved"> | null,
): MembershipAuthorizer {
  return async ({ telegramUserId, telegramChatId }) => {
    if (!approval) return { approved: false } satisfies MembershipDenial;
    return { approved: true, ...approval, telegramUserId, telegramChatId };
  };
}

/** MOCK callback that returns UUIDs not matching the verified request facts. */
export function mockMismatchedAuthorizer(
  approval: MembershipApproval,
): MembershipAuthorizer {
  return async () => approval;
}

export function failingAuthorizer(): MembershipAuthorizer {
  return async () => {
    throw new Error("membership source down");
  };
}

/** Generated Ed25519 fixture key pair — NOT Telegram's production key. */
export function generatedInitDataKeypair() {
  const secret = webcrypto.getRandomValues(new Uint8Array(32));
  const publicKeyHex = Buffer.from(ed25519.getPublicKey(secret)).toString("hex");
  return { secret, publicKeyHex };
}

/** Builds a fixture initData string signed by a generated key. */
export function buildFixtureInitData(input: {
  secret: Uint8Array;
  botId: string;
  telegramUserId: number;
  authDateSeconds: number;
  extraFields?: Record<string, string>;
}): string {
  const fields: Record<string, string> = {
    auth_date: String(input.authDateSeconds),
    user: JSON.stringify({ id: input.telegramUserId, first_name: "Fixture" }),
    ...(input.extraFields ?? {}),
  };
  const signed = Object.keys(fields)
    .sort()
    .map((key) => `${key}=${fields[key]}`)
    .join("\n");
  const message = `${input.botId}:WebAppData\n${signed}`;
  const signature = Buffer.from(
    ed25519.sign(new TextEncoder().encode(message), input.secret),
  ).toString("base64url");
  const params = Object.entries(fields).map(
    ([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`,
  );
  params.push(`signature=${signature}`);
  return params.join("&");
}

/** TEST-ONLY verifier bound to a fixture key/bot id. */
export function fixtureInitDataVerifier(config: { botId: string; publicKeyHex: string }) {
  return (raw: unknown, options: { nowMs?: number }): InitDataResult =>
    verifyThirdPartyInitDataWithConfig(raw, config, options);
}
