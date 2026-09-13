/**
 * Persistence port for devnet wallet envelopes (SOURCE ONLY — no schema is
 * applied and no adapter is wired to the backend in this slice).
 *
 * Rules held by every implementation:
 *   - one persisted wallet per immutable scope
 *     (group_id, membership_id, telegram_chat_id, telegram_user_id, network);
 *   - insertion is an atomic conditional insert: a losing concurrent attempt
 *     never overwrites and never persists a second usable key;
 *   - immutable scope columns, wallet id, key version and address can never be
 *     changed after insert;
 *   - the authenticated encrypted envelope is readable only by the signer's own
 *     server-side routine, never by an API role and never by a client.
 *
 * There is deliberately NO in-memory production implementation and NO fallback:
 * an unconfigured store rejects provisioning (fail closed). Test doubles live in
 * scripts/support/, never here.
 */
import type { CustodyEnvelope } from "@/lib/custody/custody-vault.server";

/** Immutable wallet scope. Every field is server-decided or server-confirmed. */
export type WalletScope = {
  /** Trusted BRUH group UUID, from the server-owned authorization callback. */
  groupId: string;
  /** Trusted BRUH membership UUID, from the server-owned authorization callback. */
  membershipId: string;
  /** Telegram chat id, confirmed by the authorization callback. */
  telegramChatId: string;
  /** Telegram user id, taken only from the verified initData signature. */
  telegramUserId: string;
  network: "devnet";
};

/** Row as stored. `envelope` never leaves the signer. */
export type WalletRecord = {
  walletId: string;
  scope: WalletScope;
  address: string;
  wrappingKeyVersion: string;
  frozen: true;
  envelope: CustodyEnvelope;
};

/** Public metadata only: address and non-secret scope facts. */
export type WalletPublicView = {
  walletId: string;
  address: string;
  network: "devnet";
  wrappingKeyVersion: string;
  frozen: true;
};

export function publicView(record: WalletRecord): WalletPublicView {
  return {
    walletId: record.walletId,
    address: record.address,
    network: "devnet",
    wrappingKeyVersion: record.wrappingKeyVersion,
    frozen: true,
  };
}

export interface WalletStore {
  /** Existing wallet for this exact scope, or null. */
  findByScope(scope: WalletScope): Promise<WalletRecord | null>;
  /**
   * Atomic first-writer-wins insert. Resolve `{ created: true, record }` when
   * THIS call inserted, `{ created: false, record }` when a row already existed
   * for the scope (the caller then discards its unpersisted candidate). Throw on
   * any store failure so provisioning fails closed.
   */
  insertIfAbsent(
    candidate: WalletRecord,
  ): Promise<{ created: boolean; record: WalletRecord }>;
}

/**
 * Production adapter is NOT implemented in this slice: the wallet envelope
 * schema is proposed only (docs/proposed-migration-wallets.sql) and has not been
 * applied. Returning null makes provisioning reject with `store_unavailable`.
 */
export async function getDurableWalletStore(): Promise<WalletStore | null> {
  return null;
}
