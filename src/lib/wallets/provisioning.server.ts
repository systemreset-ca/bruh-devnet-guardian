/**
 * Persistent devnet wallet provisioning service (SOURCE ONLY).
 *
 * Nothing here is applied, deployed, enabled or funded:
 *   - the wallet schema is a proposal (docs/proposed-migration-wallets.sql);
 *   - no HTTP route imports this module;
 *   - the enable gate defaults to false, every account is frozen, and there is
 *     no deposit, signing, broadcast, withdraw, export or mainnet path.
 *
 * Request authorization requires ALL of:
 *   1. the existing durable HMAC request authentication (single-use nonce),
 *   2. pinned production Telegram initData Ed25519 verification (no bot token),
 *   3. an explicit server-owned membership authorization callback.
 * Group and membership UUIDs come only from (3). initData and client-selected
 * group values are never trusted for membership, and a missing callback rejects.
 *
 * Server decides walletId, key version, address and envelope. The client body
 * may carry only the raw initData string and the claimed chat id; any other
 * field is a malformed request.
 *
 * Seed material and the wrapping key never leave the signer: the response is
 * public metadata only (wallet id, address, network, key version, frozen).
 */
import { randomUUID } from "node:crypto";
import type { DevnetCustodyVault } from "@/lib/custody/custody-vault.server";
import {
  verifySignerRequest,
  type NonceConsumer,
} from "@/lib/custody/request-auth.server";
import {
  verifyThirdPartyInitData,
  type InitDataResult,
} from "@/lib/telegram/init-data.server";
import {
  validateApproval,
  type MembershipAuthorizer,
} from "./authorization.server";
import { InvalidWalletRecord, parseWalletRecord } from "./wallet-record.server";
import {
  publicView,
  type WalletPublicView,
  type WalletRecord,
  type WalletScope,
  type WalletStore,
} from "./wallet-store.server";

export type ProvisionFailure =
  | "provisioning_disabled"
  | "method_not_allowed"
  | "unauthorized"
  | "malformed_request"
  | "initdata_rejected"
  | "authorization_unavailable"
  | "not_authorized_member"
  | "wrapping_key_unavailable"
  | "store_unavailable"
  | "inconsistent_mapping"
  | "store_record_invalid"
  | "store_error";

export type ProvisionOutcome =
  | { ok: true; created: boolean; wallet: WalletPublicView }
  | { ok: false; reason: ProvisionFailure };


const TELEGRAM_CHAT_ID = /^-?[0-9]{1,20}$/;
const ALLOWED_BODY_KEYS = ["telegram_init_data", "telegram_chat_id"] as const;

/** Strict body parse. Rejects unknown fields, so a client cannot supply a
 * wallet id, key version, envelope, address or key material. */
function parseBody(
  rawBody: string,
): { ok: true; initData: string; telegramChatId: string } | { ok: false } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return { ok: false };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false };
  }
  const keys = Object.keys(parsed);
  if (
    keys.length !== ALLOWED_BODY_KEYS.length ||
    !ALLOWED_BODY_KEYS.every((key) => keys.includes(key))
  ) {
    return { ok: false };
  }
  const body = parsed as Record<string, unknown>;
  const initData = body["telegram_init_data"];
  const chatId = body["telegram_chat_id"];
  if (
    typeof initData !== "string" ||
    initData.length === 0 ||
    typeof chatId !== "string" ||
    !TELEGRAM_CHAT_ID.test(chatId)
  ) {
    return { ok: false };
  }
  return { ok: true, initData, telegramChatId: chatId };
}

export async function provisionDevnetWallet(input: {
  /** Enable gate. Defaults to false at every call site; false rejects. */
  enabled: boolean;
  request: { method: string; path: string; headers: Headers; rawBody: string };
  auth: {
    secret: string | undefined;
    expectedKeyId: string | undefined;
    consumeNonce: NonceConsumer | undefined | null;
  };
  /** Server-owned trusted membership callback. Missing → reject. */
  authorizer: MembershipAuthorizer | undefined | null;
  /** Vault built from an explicitly injected non-extractable wrapping key. */
  vault: DevnetCustodyVault | undefined | null;
  store: WalletStore | undefined | null;
  now?: number;
  /** Test seam only; the wallet UUID is always server-generated. */
  newWalletId?: () => string;
  /**
   * TEST-ONLY seam. Defaults to the pinned production verifier (real bot id and
   * Telegram production public key). A test suite overrides it to exercise the
   * downstream flow with generated-key fixtures, which the production default
   * rejects.
   */
  verifyInitData?: (raw: unknown, options: { nowMs?: number }) => InitDataResult;
}): Promise<ProvisionOutcome> {
  if (input.enabled !== true) return { ok: false, reason: "provisioning_disabled" };

  // Provisioning is a POST-only operation; no other verb reaches any check.
  if (input.request.method !== "POST") return { ok: false, reason: "method_not_allowed" };

  const auth = await verifySignerRequest({
    method: input.request.method,
    path: input.request.path,
    headers: input.request.headers,
    rawBody: input.request.rawBody,
    secret: input.auth.secret,
    expectedKeyId: input.auth.expectedKeyId,
    consumeNonce: input.auth.consumeNonce,
    ...(input.now === undefined ? {} : { now: input.now }),
  });
  // Uniform opaque failure: never reveals which auth check failed.
  if (!auth.ok) return { ok: false, reason: "unauthorized" };

  const body = parseBody(input.request.rawBody);
  if (!body.ok) return { ok: false, reason: "malformed_request" };

  const initData = (input.verifyInitData ?? verifyThirdPartyInitData)(
    body.initData,
    input.now === undefined ? {} : { nowMs: input.now },
  );
  if (!initData.ok) return { ok: false, reason: "initdata_rejected" };

  if (typeof input.authorizer !== "function") {
    return { ok: false, reason: "authorization_unavailable" };
  }
  const request = {
    telegramUserId: initData.telegramUserId,
    telegramChatId: body.telegramChatId,
  };
  let approval;
  try {
    approval = validateApproval(request, await input.authorizer(request));
  } catch {
    // Never log: the error can echo request-derived values.
    return { ok: false, reason: "authorization_unavailable" };
  }
  if (!approval) return { ok: false, reason: "not_authorized_member" };

  if (!input.vault) return { ok: false, reason: "wrapping_key_unavailable" };
  if (!input.store) return { ok: false, reason: "store_unavailable" };

  const scope: WalletScope = {
    groupId: approval.groupId,
    membershipId: approval.membershipId,
    telegramChatId: approval.telegramChatId,
    telegramUserId: approval.telegramUserId,
    network: "devnet",
  };

  const store = input.store;
  let validated: { created: boolean; record: WalletRecord };
  try {
    // Nothing a store returns is trusted: every row is re-parsed against this
    // exact scope, including envelope structure and envelope↔row bindings.
    const existing = await store.findByScope(scope);
    if (existing !== null) {
      const record = parseWalletRecord(existing, scope);
      return { ok: true, created: false, wallet: publicView(record) };
    }

    // One wallet per Telegram identity: a different group/membership UUID
    // mapping must not be able to mint a second wallet for the same user.
    const byIdentity = await store.findByTelegramIdentity({
      telegramChatId: scope.telegramChatId,
      telegramUserId: scope.telegramUserId,
      network: "devnet",
    });
    if (byIdentity !== null) {
      const mapped = byIdentity.scope;
      const consistent =
        mapped.groupId === scope.groupId &&
        mapped.membershipId === scope.membershipId &&
        mapped.telegramChatId === scope.telegramChatId &&
        mapped.telegramUserId === scope.telegramUserId &&
        mapped.network === "devnet";
      // Either the scope lookup above should have found it (consistent mapping,
      // so the store is contradicting itself) or the mapping changed. Both are
      // fail-closed conditions; never provision a second wallet.
      return { ok: false, reason: consistent ? "store_record_invalid" : "inconsistent_mapping" };
    }

    // Server-generated identity; never client-supplied.
    const walletId = (input.newWalletId ?? randomUUID)();
    const envelope = await input.vault.provision({
      walletId,
      groupId: scope.groupId,
      membershipId: scope.membershipId,
      network: "devnet",
    });
    const candidate: WalletRecord = {
      walletId,
      scope,
      address: envelope.address,
      wrappingKeyVersion: envelope.wrappingKeyVersion,
      frozen: true,
      envelope,
    };
    // Atomic first-writer-wins: a losing race returns the persisted row, and the
    // candidate envelope is discarded unpersisted — no orphaned usable key, no
    // overwrite of an existing wallet.
    const result = await store.insertIfAbsent(candidate);
    validated = {
      created: result.created === true,
      // The winning row is validated exactly like a pre-existing row.
      record: parseWalletRecord(result.record, scope),
    };
  } catch (error) {
    if (error instanceof InvalidWalletRecord) {
      return { ok: false, reason: "store_record_invalid" };
    }
    return { ok: false, reason: "store_error" };
  }
  return { ok: true, created: validated.created, wallet: publicView(validated.record) };
}

