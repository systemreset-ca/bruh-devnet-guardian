/**
 * Fail-closed authentication foundation for signer HTTP routes.
 *
 * Properties:
 *   - the caller secret must exist in the server environment; a missing or
 *     short secret rejects every request (no demo/default/fallback secret)
 *   - HMAC-SHA256 over a canonical string binding version, method, path,
 *     timestamp, nonce and a SHA-256 digest of the exact raw body
 *   - timestamp skew window, and single-use nonce replay rejection
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
const NONCE_TTL_MS = 5 * 60_000;
const MAX_BODY_BYTES = 64 * 1024;
const MIN_SECRET_LENGTH = 32;

export type AuthFailure =
  | "secret_unavailable"
  | "malformed_request"
  | "body_too_large"
  | "stale_timestamp"
  | "replayed_nonce"
  | "bad_signature";

export type AuthResult =
  | { ok: true; keyId: string; nonce: string }
  | { ok: false; reason: AuthFailure };

const seenNonces = new Map<string, number>();

function rememberNonce(nonce: string, now: number): boolean {
  for (const [key, expiry] of seenNonces) if (expiry <= now) seenNonces.delete(key);
  if (seenNonces.has(nonce)) return false;
  if (seenNonces.size >= 10_000) return false;
  seenNonces.set(nonce, now + NONCE_TTL_MS);
  return true;
}

/** Test hook only; never called from route code. */
export function __resetNonceStore() {
  seenNonces.clear();
}

export function canonicalString(input: {
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  bodyDigestHex: string;
}): string {
  return [
    AUTH_SCHEME,
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
 * Read the secret inside the handler (per-request env injection), then pass it.
 */
export function verifySignerRequest(input: {
  method: string;
  path: string;
  headers: Headers;
  rawBody: string;
  secret: string | undefined;
  now?: number;
}): AuthResult {
  const secret = input.secret;
  if (typeof secret !== "string" || secret.length < MIN_SECRET_LENGTH) {
    return { ok: false, reason: "secret_unavailable" };
  }
  if (Buffer.byteLength(input.rawBody, "utf8") > MAX_BODY_BYTES) {
    return { ok: false, reason: "body_too_large" };
  }

  const timestamp = input.headers.get(HEADER_TIMESTAMP) ?? "";
  const nonce = input.headers.get(HEADER_NONCE) ?? "";
  const signature = (input.headers.get(HEADER_SIGNATURE) ?? "").toLowerCase();
  const keyId = input.headers.get(HEADER_KEY_ID) ?? "";

  if (
    !/^[0-9]{10,16}$/.test(timestamp) ||
    !/^[0-9a-f]{32,64}$/i.test(nonce) ||
    !/^[0-9a-f]{64}$/.test(signature) ||
    !/^[a-zA-Z0-9._-]{1,64}$/.test(keyId)
  ) {
    return { ok: false, reason: "malformed_request" };
  }

  const now = input.now ?? Date.now();
  if (Math.abs(now - Number(timestamp)) > MAX_SKEW_MS) {
    return { ok: false, reason: "stale_timestamp" };
  }

  const expected = signCanonical(
    secret,
    canonicalString({
      method: input.method,
      path: input.path,
      timestamp,
      nonce: nonce.toLowerCase(),
      bodyDigestHex: bodyDigestHex(input.rawBody),
    }),
  );
  if (!equalHex(signature, expected)) return { ok: false, reason: "bad_signature" };

  // Nonce is consumed only after the signature proves the caller.
  if (!rememberNonce(nonce.toLowerCase(), now)) return { ok: false, reason: "replayed_nonce" };

  return { ok: true, keyId, nonce: nonce.toLowerCase() };
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
