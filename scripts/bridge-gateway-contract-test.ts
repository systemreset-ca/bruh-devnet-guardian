/**
 * Gateway-side contract tests for the isolated signer bridge.
 *
 * Verifies the protocol contract the calling BRUH backend must satisfy, against
 * the ported verifier only: path allowlist, canonical binding, public-key-only
 * exchange, 8 KiB payload cap, exact 4-key payload shape and the fixed
 * 300-second nonce retention that the receiver claims.
 *
 * Offline. Real ephemeral Ed25519 signatures, no network, no Telegram, no
 * wallet, no funding, no mainnet. Booleans only in the output.
 */
import { randomBytes } from "node:crypto";
import {
  bridgeCallerPublicKey,
  signBridgeRequest,
  verifyBridgeRequest,
  type BridgeNonceConsumer,
} from "../src/lib/custody/bridge-auth.server";

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean) {
  if (ok) {
    pass += 1;
    console.log(`PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL  ${name}`);
  }
}

const SECRET = randomBytes(48).toString("hex");
const KEY_ID = "bruh-backend-test";
const PROVISION = "/api/internal/custody/provision";
const MEMBERSHIP = "/api/internal/custody/membership";
const NOW = 1_760_000_000_000;

const PAYLOAD = JSON.stringify({
  version: 1,
  telegram_init_data: "fixture-init-data",
  telegram_chat_id: "-1001234567890",
  membership_approval: {
    approved: true,
    groupId: "11111111-1111-4111-8111-111111111111",
    membershipId: "22222222-2222-4222-8222-222222222222",
    telegramChatId: "-1001234567890",
    telegramUserId: "987654321",
  },
});

function nonceStore(): BridgeNonceConsumer & { windows: number[] } {
  const used = new Set<string>();
  const windows: number[] = [];
  const fn = (async ({ keyId, nonce, now, expiresAt }) => {
    windows.push(expiresAt - now);
    const key = `${keyId}\n${nonce}`;
    if (used.has(key)) return false;
    used.add(key);
    return true;
  }) as BridgeNonceConsumer & { windows: number[] };
  fn.windows = windows;
  return fn;
}

async function verify(input: {
  rawBody?: string;
  path?: string;
  headers?: Headers;
  method?: string;
  publicKey?: string | undefined;
  keyId?: string | undefined;
  consumeNonce?: BridgeNonceConsumer | null;
  clock?: () => number;
}): Promise<boolean> {
  const rawBody = input.rawBody ?? PAYLOAD;
  const path = input.path ?? PROVISION;
  return verifyBridgeRequest({
    method: input.method ?? "POST",
    path,
    rawBody,
    headers: input.headers ?? signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path, rawBody, now: NOW }),
    expectedKeyId: input.keyId === undefined ? KEY_ID : input.keyId,
    expectedPublicKey: input.publicKey === undefined ? bridgeCallerPublicKey(SECRET) : input.publicKey,
    consumeNonce: input.consumeNonce === undefined ? nonceStore() : input.consumeNonce,
    clock: input.clock ?? (() => NOW),
  });
}

// ----------------------------------------------------- public-key-only exchange
{
  const publicKey = bridgeCallerPublicKey(SECRET);
  check("verification key is 64 hex characters", /^[0-9a-f]{64}$/.test(publicKey));
  check("verification key is deterministic for a secret", publicKey === bridgeCallerPublicKey(SECRET));
  check("a different service secret yields a different key", publicKey !== bridgeCallerPublicKey(randomBytes(48).toString("hex")));
  check("the verification key contains no part of the secret", !publicKey.includes(SECRET.slice(0, 16)) && !SECRET.includes(publicKey.slice(0, 16)));
  let shortRefused = false;
  try {
    bridgeCallerPublicKey("short");
  } catch {
    shortRefused = true;
  }
  check("a weak service secret is refused", shortRefused);
  check("verification needs only the public key, never a shared secret", await verify({ publicKey }));
}

// -------------------------------------------------------------- path allowlist
{
  check("provisioning path is accepted", await verify({ path: PROVISION }));
  check("membership path is accepted", await verify({ path: MEMBERSHIP }));
  for (const path of [
    "/api/internal/custody/withdraw",
    "/api/internal/custody/export",
    "/api/internal/custody/sign",
    "/api/public/signer/selftest",
    "/api/internal/custody/provision/",
  ]) {
    let signRefused = false;
    try {
      signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path, rawBody: PAYLOAD, now: NOW });
    } catch {
      signRefused = true;
    }
    check(`signing refuses ${path}`, signRefused);
    const headers = signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path: PROVISION, rawBody: PAYLOAD, now: NOW });
    check(`verification refuses ${path}`, !(await verify({ path, headers })));
  }
}

// ------------------------------------------------------------ canonical binding
{
  const headers = signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path: PROVISION, rawBody: PAYLOAD, now: NOW });
  check("an unmodified request verifies", await verify({ headers }));
  check("a changed body invalidates the signature", !(await verify({ headers, rawBody: PAYLOAD.replace("987654321", "123456789") })));
  check("a changed path invalidates the signature", !(await verify({ headers, path: MEMBERSHIP })));
  check("GET is refused", !(await verify({ headers, method: "GET" })));
  check("a substituted key id is refused", !(await verify({ headers, keyId: "other-backend" })));
  check("an absent expected key id is refused", !(await verify({ headers, keyId: undefined })));
  check("an absent pinned public key is refused", !(await verify({ headers, publicKey: undefined })));
  check("a malformed pinned public key is refused", !(await verify({ headers, publicKey: "zz" })));
  check("another service's public key is refused", !(await verify({ headers, publicKey: bridgeCallerPublicKey(randomBytes(48).toString("hex")) })));

  for (const header of ["x-bruh-bridge-key-id", "x-bruh-bridge-timestamp", "x-bruh-bridge-nonce", "x-bruh-bridge-signature"]) {
    const stripped = new Headers(headers);
    stripped.delete(header);
    check(`a request missing ${header} is refused`, !(await verify({ headers: stripped })));
  }
  const shortSignature = new Headers(headers);
  shortSignature.set("x-bruh-bridge-signature", "ab".repeat(32));
  check("a malformed signature length is refused", !(await verify({ headers: shortSignature })));
  const upperNonce = new Headers(headers);
  upperNonce.set("x-bruh-bridge-nonce", (headers.get("x-bruh-bridge-nonce") ?? "").toUpperCase());
  check("a non-canonical nonce is refused", !(await verify({ headers: upperNonce })));
  check("no HMAC header is part of the contract", !JSON.stringify([...headers]).toLowerCase().includes("x-bruh-signature"));
}

// ----------------------------------------------------------------- clock window
{
  check("a 59-second-old request verifies", await verify({ clock: () => NOW + 59_000 }));
  check("a 61-second-old request is refused", !(await verify({ clock: () => NOW + 61_000 })));
  check("a request 61 seconds in the future is refused", !(await verify({ clock: () => NOW - 61_000 })));
  // Freshness is re-checked after the durable claim completes.
  let calls = 0;
  const drifting = () => {
    calls += 1;
    return calls === 1 ? NOW : NOW + 120_000;
  };
  check("a claim that completes outside the window is refused", !(await verify({ clock: drifting })));
}

// ------------------------------------------------------- durable claim contract
{
  const store = nonceStore();
  const headers = signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path: PROVISION, rawBody: PAYLOAD, now: NOW });
  check("first claim accepted", await verify({ headers, consumeNonce: store }));
  check("replay of the same claim refused", !(await verify({ headers, consumeNonce: store })));
  check("retention requested is exactly 300 seconds", store.windows.every((w) => w === 300_000) && store.windows.length === 2);
  check("an absent nonce store refuses", !(await verify({ consumeNonce: null })));
  check("a refusing nonce store refuses", !(await verify({ consumeNonce: (async () => false) as BridgeNonceConsumer })));
  check("a failing nonce store refuses", !(await verify({ consumeNonce: (async () => { throw new Error("down"); }) as BridgeNonceConsumer })));
  check("a non-boolean claim result refuses", !(await verify({ consumeNonce: (async () => "yes") as unknown as BridgeNonceConsumer })));
  let claimed = false;
  await verify({ method: "GET", consumeNonce: (async () => { claimed = true; return true; }) as BridgeNonceConsumer });
  check("a refused request never claims a nonce", claimed === false);
}

// -------------------------------------------------------------- payload envelope
{
  const big = JSON.stringify({ version: 1, telegram_init_data: "x".repeat(9000), telegram_chat_id: "-1", membership_approval: {} });
  let signRefused = false;
  try {
    signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path: PROVISION, rawBody: big, now: NOW });
  } catch {
    signRefused = true;
  }
  check("a payload above 8 KiB cannot be signed", signRefused);
  check("a payload above 8 KiB cannot be verified", !(await verify({ rawBody: big })));
  const atCap = JSON.stringify({ version: 1, pad: "x".repeat(8192 - 40) }).slice(0, 8192);
  check("a payload exactly at the cap is allowed by the transport", await verify({ rawBody: atCap }));
  const shape = Object.keys(JSON.parse(PAYLOAD) as Record<string, unknown>).sort().join(",");
  check("the signed payload has exactly the four documented keys", shape === "membership_approval,telegram_chat_id,telegram_init_data,version");
  check("the header set is exactly the four bridge headers", [...signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path: PROVISION, rawBody: PAYLOAD, now: NOW }).keys()].sort().join(",") === "content-type,x-bruh-bridge-key-id,x-bruh-bridge-nonce,x-bruh-bridge-signature,x-bruh-bridge-timestamp");
}

console.log(`\n${pass} passed, ${fail} failed`);
console.log(
  "NOTE: protocol contract only, with ephemeral service keys and synthetic payloads. Not real BRUH, Telegram or deployed-runtime proof. No schema applied, no funds, no mainnet.",
);
if (fail > 0) process.exit(1);
