/**
 * Cross-project service authentication for the isolated signer bridge — ported
 * from the Codex-reviewed public BRUH source `services/custody-signer/bridge-auth.ts`
 * at commit 400fa34a5dff899091b646a6d172feda97e65dd0 (branch
 * codex/devnet-custody-core). Only the module filename/import paths are adapted
 * to this signer; the reviewed logic is unchanged and the upstream repository is
 * not modified.
 *
 * Properties carried over deliberately:
 *  - Ed25519 service signatures; only PUBLIC verification keys are exchanged
 *    between projects. No shared HMAC secret, no elevated service key, and the
 *    diagnostic caller secret is never involved.
 *  - Canonical binding of scheme, expected key ID, POST, one of two fixed paths,
 *    timestamp, random nonce and the exact raw-body SHA-256 digest.
 *  - Explicit pinned configuration plus an atomic durable nonce claim with fixed
 *    300-second retention; the timestamp must still be fresh after the claim.
 *  - 8 KiB body cap, uniform opaque denial, nothing logged.
 *
 * A valid signature proves only WHICH backend sent the request. It grants no
 * membership, provisioning or spending permission.
 */
import { createHash, randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";

const SCHEME = "BRUH-DEVNET-BRIDGE-v1";
const PATHS = new Set(["/api/internal/custody/provision", "/api/internal/custody/membership"]);
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const HEX32 = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();

export type BridgeNonceConsumer = (input: {
  keyId: string;
  nonce: string;
  now: number;
  expiresAt: number;
}) => Promise<boolean>;

type BridgeRequest = { path: string; rawBody: string; headers: Headers };

/** Service-authentication key only, never a user's Solana wallet seed. The
 * random persistent secret is injected by the owning backend's secret manager.
 * Only its public verification key is exchanged between projects. */
function callerSeed(secret: string): Uint8Array {
  if (typeof secret !== "string" || secret.length < 64)
    throw new Error("Bridge caller key unavailable.");
  return createHash("sha256").update(`${SCHEME}:caller-key\n`).update(secret).digest();
}

export function bridgeCallerPublicKey(secret: string): string {
  const seed = callerSeed(secret);
  try {
    return Buffer.from(ed25519.getPublicKey(seed)).toString("hex");
  } finally {
    seed.fill(0);
  }
}

function canonical(
  keyId: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
): Uint8Array {
  return encoder.encode(
    [
      SCHEME,
      keyId,
      "POST",
      path,
      timestamp,
      nonce,
      createHash("sha256").update(body, "utf8").digest("hex"),
    ].join("\n"),
  );
}

function permitted(path: string, body: string) {
  return PATHS.has(path) && typeof body === "string" && Buffer.byteLength(body, "utf8") <= 8192;
}

/**
 * Signing side. In Guardian this exists only for tests and for deriving the
 * public verification key; the production receiver never holds a bridge caller
 * secret of the calling backend.
 */
export function signBridgeRequest(input: {
  secret: string;
  keyId: string;
  path: string;
  rawBody: string;
  now?: number;
}): Headers {
  if (
    typeof input.keyId !== "string" ||
    !KEY_ID.test(input.keyId) ||
    !permitted(input.path, input.rawBody)
  )
    throw new Error("Invalid bridge request.");
  const now = input.now ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("Invalid bridge clock.");
  const nonce = randomBytes(16).toString("hex");
  const timestamp = String(now);
  const seed = callerSeed(input.secret);
  try {
    const signature = Buffer.from(
      ed25519.sign(canonical(input.keyId, input.path, timestamp, nonce, input.rawBody), seed),
    ).toString("hex");
    return new Headers({
      "content-type": "application/json",
      "x-bruh-bridge-key-id": input.keyId,
      "x-bruh-bridge-timestamp": timestamp,
      "x-bruh-bridge-nonce": nonce,
      "x-bruh-bridge-signature": signature,
    });
  } finally {
    seed.fill(0);
  }
}

/** Caller proof only. Does not authorize group membership, wallet generation or
 * spending. Every production handler must independently enforce those policies.
 * Failure is opaque, and no request/credential data is logged. */
export async function verifyBridgeRequest(
  input: BridgeRequest & {
    method: string;
    expectedKeyId: string | undefined;
    expectedPublicKey: string | undefined;
    consumeNonce: BridgeNonceConsumer | null | undefined;
    clock?: () => number;
  },
): Promise<boolean> {
  try {
    if (
      input.method !== "POST" ||
      !permitted(input.path, input.rawBody) ||
      !input.expectedKeyId ||
      !KEY_ID.test(input.expectedKeyId) ||
      !input.expectedPublicKey ||
      !HEX32.test(input.expectedPublicKey) ||
      typeof input.consumeNonce !== "function"
    )
      return false;
    const keyId = input.headers.get("x-bruh-bridge-key-id") ?? "";
    const timestamp = input.headers.get("x-bruh-bridge-timestamp") ?? "";
    const nonce = input.headers.get("x-bruh-bridge-nonce") ?? "";
    const signature = input.headers.get("x-bruh-bridge-signature") ?? "";
    if (
      keyId !== input.expectedKeyId ||
      !/^[0-9]{10,16}$/.test(timestamp) ||
      !/^[0-9a-f]{32}$/.test(nonce) ||
      !/^[0-9a-f]{128}$/.test(signature)
    )
      return false;
    const clock = input.clock ?? Date.now;
    const now = clock();
    const fresh = (value: number) =>
      Number.isSafeInteger(value) && Math.abs(value - Number(timestamp)) <= 60_000;
    if (
      !fresh(now) ||
      !ed25519.verify(
        Buffer.from(signature, "hex"),
        canonical(keyId, input.path, timestamp, nonce, input.rawBody),
        Buffer.from(input.expectedPublicKey, "hex"),
      )
    )
      return false;
    const consumed = await input.consumeNonce({ keyId, nonce, now, expiresAt: now + 300_000 });
    return consumed === true && fresh(clock());
  } catch {
    return false;
  }
}
