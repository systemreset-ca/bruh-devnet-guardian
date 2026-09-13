/**
 * Offline tests for the ported isolated-signer bridge receiver and verifier.
 *
 * Service signatures are ACTUAL ephemeral Ed25519 signatures over the canonical
 * string. Telegram verification and the provisioning callback are fixtures, so
 * this is NOT real Telegram, real BRUH membership or deployed-runtime proof.
 * No funding, signing, broadcast, schema application or mainnet.
 *
 * Output is booleans only: no secret, key, header, body or address is printed.
 */
import { randomBytes } from "node:crypto";
import { Keypair } from "@solana/web3.js";
import {
  bridgeCallerPublicKey,
  signBridgeRequest,
  type BridgeNonceConsumer,
} from "../src/lib/custody/bridge-auth.server";
import {
  receiveProvisionBridge,
  type BridgeReceiverDeps,
  type VerifiedProvisionScope,
} from "../src/lib/wallets/bridge-receiver.server";
import { createEphemeralWrappingKey } from "../src/lib/custody/custody-vault.server";
import { vaultFromInjection } from "../src/lib/wallets/wrapping-key.server";
import { provisionVerifiedScope } from "../src/lib/wallets/provisioning.server";
import { createInMemoryWalletStore } from "./support/wallet-fixtures";

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

const PATH = "/api/internal/custody/provision";
const ORIGIN = "https://signer.invalid.test";
const SECRET = randomBytes(48).toString("hex"); // ephemeral service secret (>=64 chars)
const PUBLIC_KEY = bridgeCallerPublicKey(SECRET);
const KEY_ID = "bruh-backend-test";
const NOW = 1_760_000_000_000;

const GROUP = "11111111-1111-4111-8111-111111111111";
const MEMBERSHIP = "22222222-2222-4222-8222-222222222222";
const CHAT = "-1001234567890";
const USER = "987654321";
const INIT_DATA = "fixture-init-data";

function createNonceStore(): BridgeNonceConsumer & { seen: () => number } {
  const used = new Set<string>();
  const consumer = (async ({ keyId, nonce, now, expiresAt }) => {
    if (expiresAt - now !== 300_000) throw new Error("nonce_ttl_out_of_range");
    const key = `${keyId}\n${nonce}`;
    if (used.has(key)) return false;
    used.add(key);
    return true;
  }) as BridgeNonceConsumer & { seen: () => number };
  consumer.seen = () => used.size;
  return consumer;
}

function approvalBody(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: 1,
    telegram_init_data: INIT_DATA,
    telegram_chat_id: CHAT,
    membership_approval: {
      approved: true,
      groupId: GROUP,
      membershipId: MEMBERSHIP,
      telegramChatId: CHAT,
      telegramUserId: USER,
    },
    ...overrides,
  });
}

function request(rawBody: string, headers: Headers, method = "POST", path = PATH): Request {
  return new Request(new URL(path, ORIGIN), { method, headers, body: method === "POST" ? rawBody : null });
}

function signed(rawBody: string, now = NOW, path = PATH): Headers {
  return signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path, rawBody, now });
}

let provisionCalls: VerifiedProvisionScope[] = [];
function deps(overrides: Partial<BridgeReceiverDeps> = {}): BridgeReceiverDeps {
  return {
    enabled: true,
    expectedKeyId: KEY_ID,
    expectedPublicKey: PUBLIC_KEY,
    consumeNonce: createNonceStore(),
    verifyTelegram: (raw) => (raw === INIT_DATA ? USER : null),
    provision: async (scope) => {
      provisionCalls.push(scope);
      return {
        created: true,
        wallet: {
          walletId: crypto.randomUUID(),
          address: Keypair.generate().publicKey.toBase58(),
          network: "devnet",
          wrappingKeyVersion: "test-v1",
          frozen: true,
        },
      };
    },
    clock: () => NOW,
    ...overrides,
  };
}

async function respond(
  rawBody: string,
  overrides: Partial<BridgeReceiverDeps> = {},
  headers?: Headers,
  method = "POST",
  path = PATH,
): Promise<Response> {
  return receiveProvisionBridge(
    request(rawBody, headers ?? signed(rawBody, NOW, path), method, path),
    deps(overrides),
  );
}

// -------------------------------------------------------------- disabled by default
{
  const body = approvalBody();
  provisionCalls = [];
  const response = await receiveProvisionBridge(request(body, signed(body)), deps({ enabled: false }));
  check("disabled receiver returns 404", response.status === 404);
  check("disabled receiver never provisions", provisionCalls.length === 0);
  check("disabled receiver response is not cached", response.headers.get("cache-control") === "no-store");
  const enabledAsString = await receiveProvisionBridge(
    request(body, signed(body)),
    deps({ enabled: "true" as unknown as boolean }),
  );
  check("only the literal boolean true enables the receiver", enabledAsString.status === 404);
}

// ------------------------------------------------------------------- happy path
{
  const body = approvalBody();
  provisionCalls = [];
  const response = await respond(body);
  const payload = (await response.json()) as Record<string, unknown>;
  check("signed approval is accepted", response.status === 200 && payload["ok"] === true);
  check("response is not cached", response.headers.get("cache-control") === "no-store");
  check("response exposes exactly the public wallet shape", Object.keys(payload).sort().join(",") === "created,ok,wallet");
  const wallet = payload["wallet"] as Record<string, unknown>;
  check("wallet metadata has exactly five public fields", Object.keys(wallet).sort().join(",") === "address,frozen,network,wallet".replace("wallet", "walletId") + ",wrappingKeyVersion");
  check("wallet is frozen devnet", wallet["network"] === "devnet" && wallet["frozen"] === true);
  check("core received exactly one verified scope", provisionCalls.length === 1);
  const scope = provisionCalls[0]!;
  check("scope carries the server-signed membership snapshot", scope.groupId === GROUP && scope.membershipId === MEMBERSHIP);
  check("scope carries the verified Telegram identity", scope.telegramChatId === CHAT && scope.telegramUserId === USER);
  check("scope is devnet and frozen at the type level", scope.network === "devnet");
  check("scope object is frozen", Object.isFrozen(scope));
}

// ---------------------------------------------------------- configuration failures
{
  const body = approvalBody();
  for (const [name, override] of [
    ["missing pinned public key", { expectedPublicKey: undefined }],
    ["malformed pinned public key", { expectedPublicKey: "not-hex" }],
    ["missing expected key id", { expectedKeyId: undefined }],
    ["missing durable nonce store", { consumeNonce: null }],
    ["failing durable nonce store", { consumeNonce: (async () => { throw new Error("down"); }) as BridgeNonceConsumer }],
    ["nonce store refusing the claim", { consumeNonce: (async () => false) as BridgeNonceConsumer }],
  ] as [string, Partial<BridgeReceiverDeps>][]) {
    provisionCalls = [];
    const response = await respond(body, override);
    check(`${name} denies with 401`, response.status === 401);
    check(`${name} never reaches the provisioning core`, provisionCalls.length === 0);
  }
}

// ------------------------------------------------------------------ auth failures
{
  const body = approvalBody();
  provisionCalls = [];
  check("unsigned request denied", (await respond(body, {}, new Headers({ "content-type": "application/json" }))).status === 401);

  const wrongSecret = randomBytes(48).toString("hex");
  const forged = signBridgeRequest({ secret: wrongSecret, keyId: KEY_ID, path: PATH, rawBody: body, now: NOW });
  check("signature from another service key denied", (await respond(body, {}, forged)).status === 401);

  const wrongKeyId = signBridgeRequest({ secret: SECRET, keyId: "other-backend", path: PATH, rawBody: body, now: NOW });
  check("key-id substitution denied", (await respond(body, {}, wrongKeyId)).status === 401);

  const otherPath = signBridgeRequest({ secret: SECRET, keyId: KEY_ID, path: "/api/internal/custody/membership", rawBody: body, now: NOW });
  check("signature bound to another path denied", (await respond(body, {}, otherPath)).status === 401);

  const tampered = signed(body);
  check("body tampering after signing denied", (await respond(approvalBody({ telegram_chat_id: "-1009999999999" }), {}, tampered)).status === 401);

  check("stale timestamp denied", (await respond(body, {}, signed(body, NOW - 61_000))).status === 401);
  check("future timestamp denied", (await respond(body, {}, signed(body, NOW + 61_000))).status === 401);
  check("GET denied", (await respond(body, {}, signed(body), "GET")).status === 401);
  check("no HMAC header path exists", !JSON.stringify([...signed(body)]).includes("x-bruh-signature"));
  check("nothing reached the core during auth failures", provisionCalls.length === 0);
}

// ------------------------------------------------------------------------- replay
{
  const body = approvalBody();
  const store = createNonceStore();
  const headers = signed(body);
  provisionCalls = [];
  const first = await receiveProvisionBridge(request(body, headers), deps({ consumeNonce: store }));
  const replay = await receiveProvisionBridge(request(body, headers), deps({ consumeNonce: store }));
  check("first signed request accepted", first.status === 200);
  check("byte-identical replay denied by the one-time claim", replay.status === 401);
  check("replay never reached the core", provisionCalls.length === 1);
  check("exactly one nonce was claimed", store.seen() === 1);
}

// --------------------------------------------------------- approval body contract
{
  const cases: [string, string][] = [
    ["unknown version", approvalBody({ version: 2 })],
    ["extra top-level field", JSON.stringify({ ...JSON.parse(approvalBody()), extra: 1 })],
    ["missing approval", JSON.stringify({ version: 1, telegram_init_data: INIT_DATA, telegram_chat_id: CHAT })],
    ["approved not true", approvalBody({ membership_approval: { approved: "yes", groupId: GROUP, membershipId: MEMBERSHIP, telegramChatId: CHAT, telegramUserId: USER } })],
    ["extra approval field", approvalBody({ membership_approval: { approved: true, groupId: GROUP, membershipId: MEMBERSHIP, telegramChatId: CHAT, telegramUserId: USER, walletId: crypto.randomUUID() } })],
    ["non-uuid group", approvalBody({ membership_approval: { approved: true, groupId: "group-1", membershipId: MEMBERSHIP, telegramChatId: CHAT, telegramUserId: USER } })],
    ["chat mismatch between body and approval", approvalBody({ membership_approval: { approved: true, groupId: GROUP, membershipId: MEMBERSHIP, telegramChatId: "-1009999999999", telegramUserId: USER } })],
    ["non-canonical user id", approvalBody({ membership_approval: { approved: true, groupId: GROUP, membershipId: MEMBERSHIP, telegramChatId: CHAT, telegramUserId: "0987654321" } })],
    ["out-of-range user id", approvalBody({ membership_approval: { approved: true, groupId: GROUP, membershipId: MEMBERSHIP, telegramChatId: CHAT, telegramUserId: "99999999999999999" } })],
    ["empty init data", approvalBody({ telegram_init_data: "" })],
    ["oversized init data", approvalBody({ telegram_init_data: "x".repeat(5000) })],
    ["array body", JSON.stringify([approvalBody()])],
    ["not json", "{"],
  ];
  for (const [name, body] of cases) {
    provisionCalls = [];
    const response = await respond(body);
    check(`${name} denied`, response.status === 401);
    check(`${name} never provisioned`, provisionCalls.length === 0);
  }
  // 8 KiB streamed cap
  provisionCalls = [];
  const huge = approvalBody({ telegram_init_data: "x".repeat(9000) });
  check("body above the 8 KiB cap denied", (await respond(huge)).status === 401);
  check("oversized body never provisioned", provisionCalls.length === 0);
}

// --------------------------------------------------- Telegram binding is mandatory
{
  const body = approvalBody();
  provisionCalls = [];
  check("rejected Telegram verification denies", (await respond(body, { verifyTelegram: () => null })).status === 401);
  check("different verified user than the approval denies", (await respond(body, { verifyTelegram: () => "123456789" })).status === 401);
  check("throwing Telegram verifier denies", (await respond(body, { verifyTelegram: () => { throw new Error("bad"); } })).status === 503);
  check("Telegram failures never provisioned", provisionCalls.length === 0);
  let seenNow = 0;
  await respond(body, { verifyTelegram: (raw, now) => { seenNow = now; return raw === INIT_DATA ? USER : null; } });
  check("Telegram verifier receives the server clock", seenNow === NOW);
}

// ------------------------------------------------------- provisioning result contract
{
  const body = approvalBody();
  const bad: [string, unknown][] = [
    ["non-object result", "ok"],
    ["missing wallet", { created: true }],
    ["extra result field", { created: true, wallet: { walletId: crypto.randomUUID(), address: Keypair.generate().publicKey.toBase58(), network: "devnet", wrappingKeyVersion: "v1", frozen: true }, envelope: {} }],
    ["non-boolean created", { created: "yes", wallet: { walletId: crypto.randomUUID(), address: Keypair.generate().publicKey.toBase58(), network: "devnet", wrappingKeyVersion: "v1", frozen: true } }],
    ["envelope field on wallet", { created: true, wallet: { walletId: crypto.randomUUID(), address: Keypair.generate().publicKey.toBase58(), network: "devnet", wrappingKeyVersion: "v1", frozen: true, encryptedSeed: "AAAA" } }],
    ["unfrozen wallet", { created: true, wallet: { walletId: crypto.randomUUID(), address: Keypair.generate().publicKey.toBase58(), network: "devnet", wrappingKeyVersion: "v1", frozen: false } }],
    ["mainnet wallet", { created: true, wallet: { walletId: crypto.randomUUID(), address: Keypair.generate().publicKey.toBase58(), network: "mainnet-beta", wrappingKeyVersion: "v1", frozen: true } }],
    ["non-base58 address", { created: true, wallet: { walletId: crypto.randomUUID(), address: "not an address", network: "devnet", wrappingKeyVersion: "v1", frozen: true } }],
    ["non-uuid wallet id", { created: true, wallet: { walletId: "wallet-1", address: Keypair.generate().publicKey.toBase58(), network: "devnet", wrappingKeyVersion: "v1", frozen: true } }],
  ];
  for (const [name, result] of bad) {
    const response = await respond(body, { provision: async () => result as never });
    check(`${name} refused with 503, not 200`, response.status === 503);
    const text = await response.text();
    check(`${name} leaks no result text`, text === JSON.stringify({ ok: false }));
  }
  const denied = await respond(body, { provision: async () => { throw new Error("provisioning_unavailable"); } });
  check("a denied provisioning core never becomes a 200", denied.status === 503);
  check("core failure leaks no reason", (await denied.text()) === JSON.stringify({ ok: false }));
}

// ------------------------- bridge-verified approval into the real provisioning core
{
  const vault = vaultFromInjection({ key: await createEphemeralWrappingKey(), keyVersion: "bridge-test-v1" });
  const store = createInMemoryWalletStore();
  const core: BridgeReceiverDeps["provision"] = async (scope) => {
    const outcome = await provisionVerifiedScope({ scope, vault, store });
    if (!outcome.ok) throw new Error("provisioning_unavailable");
    return { created: outcome.created, wallet: outcome.wallet };
  };
  const first = await respond(approvalBody(), { provision: core });
  const firstPayload = (await first.json()) as { created?: unknown; wallet?: { walletId?: string; address?: string } };
  check("bridge approval provisions through the shared core", first.status === 200 && firstPayload.created === true);

  const second = await respond(approvalBody(), { provision: core });
  const secondPayload = (await second.json()) as { created?: unknown; wallet?: { walletId?: string; address?: string } };
  check("repeat approval is idempotent, not a second wallet", second.status === 200 && secondPayload.created === false);
  check("repeat approval returns the same wallet", secondPayload.wallet?.walletId === firstPayload.wallet?.walletId && secondPayload.wallet?.address === firstPayload.wallet?.address);

  // A changed group/membership mapping for the same Telegram identity must not mint a second wallet.
  const remapped = approvalBody({
    membership_approval: {
      approved: true,
      groupId: "33333333-3333-4333-8333-333333333333",
      membershipId: "44444444-4444-4444-8444-444444444444",
      telegramChatId: CHAT,
      telegramUserId: USER,
    },
  });
  const third = await respond(remapped, { provision: core });
  check("changed membership mapping is refused, not a second wallet", third.status === 503);

  // Concurrent identical approvals: exactly one wallet.
  const bodies = [approvalBody(), approvalBody(), approvalBody()];
  const racing = await Promise.all(bodies.map((body) => respond(body, { provision: core })));
  check("concurrent approvals all resolve", racing.every((r) => r.status === 200));
  const ids = await Promise.all(racing.map(async (r) => ((await r.json()) as { wallet: { walletId: string } }).wallet.walletId));
  check("concurrent approvals return one wallet id", new Set([...ids, String(firstPayload.wallet?.walletId)]).size === 1);

  // Wrapping key / store absence fails closed inside the core.
  const noVault = await respond(approvalBody(), {
    provision: async (scope) => {
      const outcome = await provisionVerifiedScope({ scope, vault: null, store });
      if (!outcome.ok) throw new Error(outcome.reason);
      return { created: outcome.created, wallet: outcome.wallet };
    },
  });
  check("absent wrapping key fails closed", noVault.status === 503);
  const noStore = await respond(approvalBody(), {
    provision: async (scope) => {
      const outcome = await provisionVerifiedScope({ scope, vault, store: null });
      if (!outcome.ok) throw new Error(outcome.reason);
      return { created: outcome.created, wallet: outcome.wallet };
    },
  });
  check("absent wallet store fails closed", noStore.status === 503);
}

console.log(`\n${pass} passed, ${fail} failed`);
console.log(
  "NOTE: service signatures are ACTUAL ephemeral Ed25519 signatures; Telegram verification, membership approvals and (except in the core section) wallet callbacks are fixtures. This is NOT real Telegram, real BRUH membership or deployed-runtime proof. No schema applied, no funds, no mainnet.",
);
if (fail > 0) process.exit(1);
