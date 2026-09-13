/**
 * Fail-closed authentication foundation for signer HTTP routes.
 *
 * Properties:
 *   - the caller secret must exist in the server environment; a missing or
 *     short secret rejects every request (no demo/default/fallback secret)
 *   - the expected key ID must be configured explicitly; a caller-supplied key
 *     ID that differs is rejected, and the expected key ID is bound into the
 *     HMAC canonical input
 *   - HMAC-SHA256 over a canonical string binding version, key ID, method,
 *     path, timestamp, nonce and a SHA-256 digest of the exact raw body
 *   - timestamp skew window, plus single-use nonce replay rejection performed
 *     by an explicit, atomic, DURABLE consume callback supplied by the caller.
 *     There is no in-memory nonce store in this module: a process-local Map
 *     cannot stop replay across Worker instances or restarts. A missing or
 *     erroring nonce store rejects the request.
 *   - constant-time comparison; never logs headers, bodies or key material
 *
 * This module authenticates callers only. It performs no provisioning and no
 * signing, and it is never imported by browser code (*.server.ts is blocked
 * from client bundles).
 */
import { createHmac, createHash, timingSafeEqual, webcrypto } from "node:crypto";

export const AUTH_SCHEME = "BRUH-DEVNET-SIGNER-v1";
export const HEADER_TIMESTAMP = "x-bruh-timestamp";
export const HEADER_NONCE = "x-bruh-nonce";
export const HEADER_SIGNATURE = "x-bruh-signature";
export const HEADER_KEY_ID = "x-bruh-key-id";

const MAX_SKEW_MS = 60_000;
export const NONCE_TTL_MS = 5 * 60_000;
const MAX_BODY_BYTES = 64 * 1024;
const MIN_SECRET_LENGTH = 32;
const KEY_ID_PATTERN = /^[a-zA-Z0-9._-]{1,64}$/;

export type AuthFailure =
  | "secret_unavailable"
  | "config_unavailable"
  | "nonce_store_unavailable"
  | "malformed_request"
  | "body_too_large"
  | "stale_timestamp"
  | "unknown_key_id"
  | "replayed_nonce"
  | "bad_signature";

export type AuthResult =
  | { ok: true; keyId: string; nonce: string }
  | { ok: false; reason: AuthFailure };

/**
 * Atomic durable single-use nonce consumption.
 *
 * MUST be backed by a durable store shared by every server instance, and MUST
 * be atomic (e.g. a conditional insert on a unique key). Resolve `true` only
 * when THIS call inserted the nonce for the first time; resolve `false` when it
 * already existed. Throw or reject on any store failure — the verifier then
 * fails closed instead of accepting an unverifiable request.
 */
export type NonceConsumer = (input: {
  keyId: string;
  nonce: string;
  now: number;
  expiresAt: number;
}) => Promise<boolean>;

export function canonicalString(input: {
  keyId: string;
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  bodyDigestHex: string;
}): string {
  return [
    AUTH_SCHEME,
    input.keyId,
    input.method.toUpperCase(),
    input.path,
    input.timestamp,
    input.nonce,
    input.bodyDigestHex,
  ].join("\n");
}

export function bodyDigestHex(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

export function signCanonical(secret: string, canonical: string): string {
  return createHmac("sha256", secret).update(canonical, "utf8").digest("hex");
}

/** Random nonce helper for authenticated internal callers. */
export function newNonce(): string {
  return Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString("hex");
}

function equalHex(a: string, b: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(a) || !/^[0-9a-f]{64}$/.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

/**
 * Verify a request. `rawBody` must be the exact bytes read from the request.
 * Read the secret and expected key ID inside the handler (per-request env
 * injection), then pass them along with a durable atomic nonce consumer.
 */
export async function verifySignerRequest(input: {
  method: string;
  path: string;
  headers: Headers;
  rawBody: string;
  secret: string | undefined;
  expectedKeyId: string | undefined;
  consumeNonce: NonceConsumer | undefined | null;
  now?: number;
}): Promise<AuthResult> {
  const secret = input.secret;
  if (typeof secret !== "string" || secret.length < MIN_SECRET_LENGTH) {
    return { ok: false, reason: "secret_unavailable" };
  }
  const expectedKeyId = input.expectedKeyId;
  if (typeof expectedKeyId !== "string" || !KEY_ID_PATTERN.test(expectedKeyId)) {
    return { ok: false, reason: "config_unavailable" };
  }
  if (typeof input.consumeNonce !== "function") {
    // Fail closed: no durable nonce store means replay cannot be prevented.
    return { ok: false, reason: "nonce_store_unavailable" };
  }
  if (Buffer.byteLength(input.rawBody, "utf8") > MAX_BODY_BYTES) {
    return { ok: false, reason: "body_too_large" };
  }

  const timestamp = input.headers.get(HEADER_TIMESTAMP) ?? "";
  const nonceHeader = input.headers.get(HEADER_NONCE) ?? "";
  const signature = (input.headers.get(HEADER_SIGNATURE) ?? "").toLowerCase();
  const keyId = input.headers.get(HEADER_KEY_ID) ?? "";

  if (
    !/^[0-9]{10,16}$/.test(timestamp) ||
    !/^[0-9a-f]{32,64}$/.test(nonceHeader) ||
    !/^[0-9a-f]{64}$/.test(signature) ||
    !KEY_ID_PATTERN.test(keyId)
  ) {
    return { ok: false, reason: "malformed_request" };
  }
  const nonce = nonceHeader;

  // A caller-supplied key ID that differs from the configured expected one is
  // rejected outright, and the expected value is also bound into the HMAC.
  if (
    keyId.length !== expectedKeyId.length ||
    !timingSafeEqual(Buffer.from(keyId, "utf8"), Buffer.from(expectedKeyId, "utf8"))
  ) {
    return { ok: false, reason: "unknown_key_id" };
  }

  const now = input.now ?? Date.now();
  if (Math.abs(now - Number(timestamp)) > MAX_SKEW_MS) {
    return { ok: false, reason: "stale_timestamp" };
  }

  const expected = signCanonical(
    secret,
    canonicalString({
      keyId: expectedKeyId,
      method: input.method,
      path: input.path,
      timestamp,
      nonce,
      bodyDigestHex: bodyDigestHex(input.rawBody),
    }),
  );
  if (!equalHex(signature, expected)) return { ok: false, reason: "bad_signature" };

  // Nonce is consumed only after the signature proves the caller.
  let consumed: boolean;
  try {
    consumed = await input.consumeNonce({
      keyId: expectedKeyId,
      nonce,
      now,
      expiresAt: now + NONCE_TTL_MS,
    });
  } catch {
    // Never log the error: it can carry request-derived material.
    return { ok: false, reason: "nonce_store_unavailable" };
  }
  if (consumed !== true) return { ok: false, reason: "replayed_nonce" };

  return { ok: true, keyId: expectedKeyId, nonce };
}

/** Uniform opaque rejection. Never reveals which check failed. */
export function unauthorizedResponse(): Response {
  return new Response(JSON.stringify({ error: "unauthorized" }), {
    status: 401,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "www-authenticate": AUTH_SCHEME,
    },
  });
}
