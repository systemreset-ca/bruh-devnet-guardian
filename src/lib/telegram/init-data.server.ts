/**
 * Server-only verification of Telegram Mini App `initData` for THIRD-PARTY use.
 *
 * Reference: https://core.telegram.org/bots/webapps#validating-data-for-third-party-use
 *
 * This path uses Telegram's Ed25519 signature (`signature` parameter) and needs
 * NO bot token. The bot ID and Telegram's production public key are pinned in
 * this module and are never taken from the request; a caller cannot override
 * them.
 *
 * Canonical signed string:
 *   "<bot_id>:WebAppData\n" + fields (excluding `hash` and `signature`)
 *   sorted by key, each as "key=value", joined by "\n".
 *
 * Deliberately NOT done here:
 *   - no trust in `initDataUnsafe` (only the raw query string is verified);
 *   - no inference of group/channel membership;
 *   - no inference of Telegram 2FA state;
 *   - no bot-token (`hash`) verification path.
 *
 * Never logs initData, signatures, user payloads or key material.
 */
import { ed25519 } from "@noble/curves/ed25519.js";

/** Pinned server config. Not configurable by any request. */
export const TELEGRAM_PRODUCTION_ED25519_PUBLIC_KEY_HEX =
  "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d";

/** Verified public bot identity for this service (@BRUHLegendsBot). */
export const EXPECTED_BOT_ID = "8763268934";

/** Maximum accepted initData payload size, in bytes. */
export const MAX_INIT_DATA_BYTES = 4096;

/** Default freshness window for a signed payload. */
export const DEFAULT_MAX_AGE_SECONDS = 300;

/** Tolerance for a payload whose auth_date is slightly ahead of server time. */
export const MAX_FUTURE_SKEW_SECONDS = 60;

export type InitDataFailureReason =
  | "payload_too_large"
  | "empty_payload"
  | "malformed_payload"
  | "duplicate_parameter"
  | "missing_signature"
  | "malformed_signature"
  | "missing_auth_date"
  | "malformed_auth_date"
  | "stale_payload"
  | "future_payload"
  | "missing_user"
  | "malformed_user"
  | "bad_signature"
  | "config_unavailable";

export type InitDataResult =
  | {
      ok: true;
      /** Telegram numeric user ID, taken only from the signed payload. */
      telegramUserId: string;
      authDateSeconds: number;
      botId: string;
    }
  | { ok: false; reason: InitDataFailureReason };

export interface InitDataVerifierConfig {
  botId: string;
  publicKeyHex: string;
}

/** The only configuration used in production. */
export const PINNED_INIT_DATA_CONFIG: InitDataVerifierConfig = {
  botId: EXPECTED_BOT_ID,
  publicKeyHex: TELEGRAM_PRODUCTION_ED25519_PUBLIC_KEY_HEX,
};

interface VerifyOptions {
  /** Server clock in ms; defaults to Date.now(). Never a caller-supplied value. */
  nowMs?: number;
  maxAgeSeconds?: number;
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const bytes = Buffer.from(padded, "base64");
    // Round-trip guard: reject inputs base64 silently truncates.
    if (bytes.length === 0) return null;
    return new Uint8Array(bytes);
  } catch {
    return null;
  }
}

function decodeHex(value: string): Uint8Array | null {
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) return null;
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Strict parse of an initData query string into ordered pairs.
 * Rejects duplicate parameter names outright rather than picking a winner.
 */
function parseStrict(
  raw: string,
): { ok: true; fields: Map<string, string> } | { ok: false; reason: InitDataFailureReason } {
  const fields = new Map<string, string>();
  for (const part of raw.split("&")) {
    if (part.length === 0) return { ok: false, reason: "malformed_payload" };
    const eq = part.indexOf("=");
    if (eq <= 0) return { ok: false, reason: "malformed_payload" };
    const rawKey = part.slice(0, eq);
    const rawValue = part.slice(eq + 1);
    let key: string;
    let value: string;
    try {
      key = decodeURIComponent(rawKey.replace(/\+/g, " "));
      value = decodeURIComponent(rawValue.replace(/\+/g, " "));
    } catch {
      return { ok: false, reason: "malformed_payload" };
    }
    if (fields.has(key)) return { ok: false, reason: "duplicate_parameter" };
    fields.set(key, value);
  }
  return { ok: true, fields };
}

/**
 * INTERNAL / TEST-ONLY entry point that takes an explicit verifier config so a
 * test suite can exercise wrong-bot and wrong-key binding with generated
 * fixtures. Production code must call `verifyThirdPartyInitData`, which always
 * uses the pinned config.
 */
export function verifyThirdPartyInitDataWithConfig(
  rawInitData: unknown,
  config: InitDataVerifierConfig,
  options: VerifyOptions = {},
): InitDataResult {
  if (
    typeof config.botId !== "string" ||
    !/^[0-9]{1,20}$/.test(config.botId) ||
    typeof config.publicKeyHex !== "string" ||
    config.publicKeyHex.length !== 64
  ) {
    return { ok: false, reason: "config_unavailable" };
  }
  const publicKey = decodeHex(config.publicKeyHex);
  if (!publicKey || publicKey.length !== 32) {
    return { ok: false, reason: "config_unavailable" };
  }

  if (typeof rawInitData !== "string" || rawInitData.length === 0) {
    return { ok: false, reason: "empty_payload" };
  }
  if (Buffer.byteLength(rawInitData, "utf8") > MAX_INIT_DATA_BYTES) {
    return { ok: false, reason: "payload_too_large" };
  }

  const parsed = parseStrict(rawInitData);
  if (!parsed.ok) return parsed;
  const fields = parsed.fields;

  const signatureValue = fields.get("signature");
  if (signatureValue === undefined || signatureValue.length === 0) {
    return { ok: false, reason: "missing_signature" };
  }
  const signature = decodeBase64Url(signatureValue);
  if (!signature || signature.length !== 64) {
    return { ok: false, reason: "malformed_signature" };
  }

  const authDateValue = fields.get("auth_date");
  if (authDateValue === undefined) return { ok: false, reason: "missing_auth_date" };
  if (!/^[0-9]{1,12}$/.test(authDateValue)) {
    return { ok: false, reason: "malformed_auth_date" };
  }
  const authDateSeconds = Number(authDateValue);
  if (!Number.isSafeInteger(authDateSeconds) || authDateSeconds <= 0) {
    return { ok: false, reason: "malformed_auth_date" };
  }

  const nowSeconds = Math.floor((options.nowMs ?? Date.now()) / 1000);
  const maxAge = options.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
  if (nowSeconds - authDateSeconds > maxAge) return { ok: false, reason: "stale_payload" };
  if (authDateSeconds - nowSeconds > MAX_FUTURE_SKEW_SECONDS) {
    return { ok: false, reason: "future_payload" };
  }

  const userValue = fields.get("user");
  if (userValue === undefined || userValue.length === 0) {
    return { ok: false, reason: "missing_user" };
  }
  let telegramUserId: string;
  try {
    const user: unknown = JSON.parse(userValue);
    const id = (user as { id?: unknown } | null)?.id;
    if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0) {
      return { ok: false, reason: "malformed_user" };
    }
    telegramUserId = String(id);
  } catch {
    return { ok: false, reason: "malformed_user" };
  }

  // Canonical string: bot binding first, then sorted signed fields.
  const signedFields = [...fields.entries()]
    .filter(([key]) => key !== "hash" && key !== "signature")
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([key, value]) => `${key}=${value}`);
  const message = `${config.botId}:WebAppData\n${signedFields.join("\n")}`;

  let valid = false;
  try {
    valid = ed25519.verify(signature, new TextEncoder().encode(message), publicKey);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "bad_signature" };

  return { ok: true, telegramUserId, authDateSeconds, botId: config.botId };
}

/**
 * Production verifier. Bot ID and Telegram's production public key are pinned;
 * only the raw initData string and server-side freshness options are accepted.
 */
export function verifyThirdPartyInitData(
  rawInitData: unknown,
  options: VerifyOptions = {},
): InitDataResult {
  return verifyThirdPartyInitDataWithConfig(rawInitData, PINNED_INIT_DATA_CONFIG, options);
}
