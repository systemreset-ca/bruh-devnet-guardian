/**
 * Strict parsing/validation of stored wallet rows and custody envelopes
 * (SOURCE ONLY).
 *
 * The provisioning service must never trust what a store returns — neither a
 * `findByScope` row nor the winning row of a concurrent insert. Every value is
 * re-validated here against the reviewed structure and against the exact scope
 * the caller asked for. Anything wrong, extra, missing or malformed throws, and
 * the caller fails closed. Nothing in this module logs or returns envelope
 * bytes.
 */
import bs58 from "bs58";
import type { CustodyEnvelope } from "@/lib/custody/custody-vault.server";
import type { WalletRecord, WalletScope } from "./wallet-store.server";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY_VERSION = /^[A-Za-z0-9._-]{1,64}$/;
const ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const TELEGRAM_ID = /^[0-9]{1,20}$/;
const TELEGRAM_CHAT_ID = /^-?[0-9]{1,20}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** Exact reviewed envelope shape — no extra and no missing keys. */
const ENVELOPE_KEYS = [
  "version",
  "walletId",
  "groupId",
  "membershipId",
  "network",
  "address",
  "wrappingKeyVersion",
  "seedIv",
  "encryptedSeed",
  "wrappingIv",
  "wrappedDataKey",
] as const;

const RECORD_KEYS = [
  "walletId",
  "scope",
  "address",
  "wrappingKeyVersion",
  "frozen",
  "envelope",
] as const;

const SCOPE_KEYS = [
  "groupId",
  "membershipId",
  "telegramChatId",
  "telegramUserId",
  "network",
] as const;

export class InvalidWalletRecord extends Error {
  constructor() {
    // Deliberately valueless: the message never echoes stored or request data.
    super("Invalid stored wallet record.");
  }
}

function reject(): never {
  throw new InvalidWalletRecord();
}

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) reject();
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record);
  if (actual.length !== keys.length) reject();
  for (const key of keys) if (!Object.hasOwn(record, key)) reject();
  return record;
}

/** Canonical, fixed-length base64 (round-trips byte for byte). */
function base64OfLength(value: unknown, length: number): void {
  if (typeof value !== "string" || !BASE64.test(value)) reject();
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== length || decoded.toString("base64") !== value) reject();
}

function bs58Address(value: unknown): void {
  if (typeof value !== "string" || !ADDRESS.test(value)) reject();
  let decoded: Uint8Array;
  try {
    decoded = bs58.decode(value);
  } catch {
    reject();
  }
  if (decoded.length !== 32) reject();
}

/**
 * Strict structural validation of a stored custody envelope. Structure only:
 * this does not decrypt. Authenticated decryption remains the vault's job.
 */
export function parseCustodyEnvelope(value: unknown): CustodyEnvelope {
  const raw = exactObject(value, ENVELOPE_KEYS);
  if (raw["version"] !== 1) reject();
  if (raw["network"] !== "devnet") reject();
  for (const key of ["walletId", "groupId", "membershipId"] as const) {
    const id = raw[key];
    if (typeof id !== "string" || !UUID.test(id)) reject();
  }
  if (typeof raw["wrappingKeyVersion"] !== "string" || !KEY_VERSION.test(raw["wrappingKeyVersion"])) {
    reject();
  }
  bs58Address(raw["address"]);
  base64OfLength(raw["seedIv"], 12);
  base64OfLength(raw["wrappingIv"], 12);
  // 32-byte plaintext + 16-byte GCM tag.
  base64OfLength(raw["encryptedSeed"], 48);
  base64OfLength(raw["wrappedDataKey"], 48);
  return {
    version: 1,
    walletId: raw["walletId"] as string,
    groupId: raw["groupId"] as string,
    membershipId: raw["membershipId"] as string,
    network: "devnet",
    address: raw["address"] as string,
    wrappingKeyVersion: raw["wrappingKeyVersion"] as string,
    seedIv: raw["seedIv"] as string,
    encryptedSeed: raw["encryptedSeed"] as string,
    wrappingIv: raw["wrappingIv"] as string,
    wrappedDataKey: raw["wrappedDataKey"] as string,
  };
}

function parseScope(value: unknown): WalletScope {
  const raw = exactObject(value, SCOPE_KEYS);
  if (raw["network"] !== "devnet") reject();
  for (const key of ["groupId", "membershipId"] as const) {
    const id = raw[key];
    if (typeof id !== "string" || !UUID.test(id)) reject();
  }
  const chatId = raw["telegramChatId"];
  const userId = raw["telegramUserId"];
  if (typeof chatId !== "string" || !TELEGRAM_CHAT_ID.test(chatId)) reject();
  if (typeof userId !== "string" || !TELEGRAM_ID.test(userId)) reject();
  return {
    groupId: raw["groupId"] as string,
    membershipId: raw["membershipId"] as string,
    telegramChatId: chatId,
    telegramUserId: userId,
    network: "devnet",
  };
}

/**
 * Full validation of a stored/returned wallet row against the scope that was
 * requested. Checks every expected field, then checks that the envelope's own
 * bindings equal the row's identity — a row carrying another wallet's envelope,
 * a mismatched address or a mismatched key version is rejected.
 */
export function parseWalletRecord(value: unknown, expected: WalletScope): WalletRecord {
  const raw = exactObject(value, RECORD_KEYS);
  const walletId = raw["walletId"];
  if (typeof walletId !== "string" || !UUID.test(walletId)) reject();
  if (raw["frozen"] !== true) reject();
  if (typeof raw["wrappingKeyVersion"] !== "string" || !KEY_VERSION.test(raw["wrappingKeyVersion"])) {
    reject();
  }
  bs58Address(raw["address"]);

  const scope = parseScope(raw["scope"]);
  // The row must be for the exact scope that was asked for, field by field.
  for (const key of SCOPE_KEYS) {
    if (scope[key] !== expected[key]) reject();
  }

  const envelope = parseCustodyEnvelope(raw["envelope"]);
  if (
    envelope.walletId !== walletId ||
    envelope.groupId !== scope.groupId ||
    envelope.membershipId !== scope.membershipId ||
    envelope.network !== scope.network ||
    envelope.address !== (raw["address"] as string) ||
    envelope.wrappingKeyVersion !== (raw["wrappingKeyVersion"] as string)
  ) {
    reject();
  }

  return {
    walletId,
    scope,
    address: raw["address"] as string,
    wrappingKeyVersion: raw["wrappingKeyVersion"] as string,
    frozen: true,
    envelope,
  };
}
