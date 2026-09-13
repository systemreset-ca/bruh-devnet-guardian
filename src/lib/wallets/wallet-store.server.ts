/**
 * Persistence port for devnet wallet envelopes (SOURCE ONLY — no schema is
 * applied and no adapter is wired to the backend in this slice).
 *
 * This file defines a PORT plus a controlled-RPC adapter. It is NOT a verified
 * persistent integration: the schema it targets is a proposal
 * (docs/proposed-migration-wallets.sql) that has not been applied, and
 * `getDurableWalletStore()` deliberately resolves to null until a reviewed
 * schema and configuration exist.
 *
 * Rules held by every implementation:
 *   - one persisted wallet per immutable scope
 *     (group_id, membership_id, telegram_chat_id, telegram_user_id, network);
 *   - additionally one wallet per (telegram_chat_id, telegram_user_id, network),
 *     so a different group/membership UUID mapping cannot mint a second wallet
 *     for the same Telegram identity;
 *   - insertion is an atomic conditional insert: a losing concurrent attempt
 *     never overwrites and never persists a second usable key;
 *   - immutable scope columns, wallet id, key version, address and envelope can
 *     never be changed after insert;
 *   - the authenticated encrypted envelope is readable only by the signer's own
 *     server-side routine, never by an API role and never by a client.
 *
 * There is deliberately NO in-memory production implementation and NO fallback:
 * an unconfigured store rejects provisioning (fail closed). Test doubles live in
 * scripts/support/, never here.
 */
import type { CustodyEnvelope } from "@/lib/custody/custody-vault.server";
import { parseWalletRecord } from "./wallet-record.server";

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

/** The Telegram identity a wallet belongs to, independent of UUID mapping. */
export type TelegramWalletIdentity = {
  telegramChatId: string;
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

/**
 * Public projection of an ALREADY VALIDATED record. Nothing is assumed: network
 * and frozen are read from the record and re-asserted, never hardcoded.
 */
export function publicView(record: WalletRecord): WalletPublicView {
  if (
    record.scope.network !== "devnet" ||
    record.envelope.network !== "devnet" ||
    record.frozen !== true
  ) {
    throw new Error("Refusing to project an invalid wallet record.");
  }
  return {
    walletId: record.walletId,
    address: record.address,
    network: record.scope.network,
    wrappingKeyVersion: record.wrappingKeyVersion,
    frozen: record.frozen,
  };
}

export interface WalletStore {
  /** Existing wallet for this exact scope, or null. */
  findByScope(scope: WalletScope): Promise<WalletRecord | null>;
  /**
   * Existing wallet for this Telegram identity under ANY group/membership
   * mapping, or null. Used to fail closed on an inconsistent mapping instead of
   * minting a second wallet for the same Telegram user.
   */
  findByTelegramIdentity(
    identity: TelegramWalletIdentity,
  ): Promise<{ walletId: string; scope: WalletScope } | null>;
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
 * Narrow controlled RPC callback: the ONLY database surface this adapter may
 * touch. It calls named server-side routines with named parameters, never
 * arbitrary SQL, and it is always injected explicitly (no ambient client, no
 * credential read in this module).
 */
export type WalletRpc = (
  routine:
    | "provision_devnet_wallet"
    | "read_devnet_wallet_scoped"
    | "read_devnet_wallet_by_telegram"
    | "read_devnet_wallet_envelope",
  params: Record<string, unknown>,
) => Promise<unknown>;

function firstRow(result: unknown): Record<string, unknown> | null {
  if (result === null || result === undefined) return null;
  const rows = Array.isArray(result) ? result : [result];
  if (rows.length === 0) return null;
  if (rows.length > 1) throw new Error("Ambiguous wallet result.");
  const row = rows[0];
  if (typeof row !== "object" || row === null || Array.isArray(row)) {
    throw new Error("Malformed wallet result.");
  }
  return row as Record<string, unknown>;
}

function str(value: unknown): string {
  if (typeof value !== "string") throw new Error("Malformed wallet result.");
  return value;
}

/**
 * Controlled-RPC wallet store. Every routine result is re-validated by
 * parseWalletRecord/structural checks against the requested scope before it is
 * returned, so a wrong, extra or malformed row fails closed rather than being
 * trusted. Not exercised against an applied schema in this slice.
 */
export function createRpcWalletStore(rpc: WalletRpc): WalletStore {
  async function readScoped(scope: WalletScope): Promise<WalletRecord | null> {
    const row = firstRow(
      await rpc("read_devnet_wallet_scoped", {
        p_group_id: scope.groupId,
        p_membership_id: scope.membershipId,
        p_telegram_chat_id: scope.telegramChatId,
        p_telegram_user_id: scope.telegramUserId,
      }),
    );
    if (!row) return null;
    // Rebuild the candidate shape from named columns, then validate strictly.
    const envelope = firstRow(
      await rpc("read_devnet_wallet_envelope", {
        p_wallet_id: row["wallet_id"],
        p_group_id: scope.groupId,
        p_membership_id: scope.membershipId,
        p_telegram_chat_id: scope.telegramChatId,
        p_telegram_user_id: scope.telegramUserId,
      }),
    );
    return parseWalletRecord(
      {
        walletId: str(row["wallet_id"]),
        scope,
        address: str(row["address"]),
        wrappingKeyVersion: str(row["wrapping_key_version"]),
        frozen: row["frozen"],
        envelope: envelope?.["envelope"] ?? envelope,
      },
      scope,
    );
  }

  return {
    findByScope: readScoped,

    async findByTelegramIdentity(identity) {
      const row = firstRow(
        await rpc("read_devnet_wallet_by_telegram", {
          p_telegram_chat_id: identity.telegramChatId,
          p_telegram_user_id: identity.telegramUserId,
        }),
      );
      if (!row) return null;
      return {
        walletId: str(row["wallet_id"]),
        scope: {
          groupId: str(row["group_id"]),
          membershipId: str(row["membership_id"]),
          telegramChatId: str(row["telegram_chat_id"]),
          telegramUserId: str(row["telegram_user_id"]),
          network: "devnet",
        },
      };
    },

    async insertIfAbsent(candidate) {
      const row = firstRow(
        await rpc("provision_devnet_wallet", {
          p_wallet_id: candidate.walletId,
          p_group_id: candidate.scope.groupId,
          p_membership_id: candidate.scope.membershipId,
          p_telegram_chat_id: candidate.scope.telegramChatId,
          p_telegram_user_id: candidate.scope.telegramUserId,
          p_wrapping_key_version: candidate.wrappingKeyVersion,
          p_address: candidate.address,
          p_envelope: candidate.envelope,
        }),
      );
      if (!row) throw new Error("Provisioning returned no row.");
      const created = row["created"];
      if (typeof created !== "boolean") throw new Error("Malformed wallet result.");
      // Re-read and re-validate the persisted row; never trust the write result.
      const record = await readScoped(candidate.scope);
      if (!record) throw new Error("Provisioned wallet is not readable.");
      if (created && record.walletId !== candidate.walletId) {
        throw new Error("Provisioning identity mismatch.");
      }
      return { created, record };
    },
  };
}

/**
 * Production adapter is NOT configured in this slice: the wallet envelope
 * schema is proposed only (docs/proposed-migration-wallets.sql) and has not been
 * applied, and no reviewed RPC configuration exists. Returning null makes
 * provisioning reject with `store_unavailable`.
 */
export async function getDurableWalletStore(): Promise<WalletStore | null> {
  return null;
}
