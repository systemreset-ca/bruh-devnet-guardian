/**
 * Source-only tests for persistent devnet wallet provisioning.
 *
 * Offline: no database, no network, no funding, no broadcast, no mainnet, no
 * secrets. Seed material and wrapping keys stay in memory and are never printed.
 * All accepted paths use MOCK membership approval callbacks and generated-key
 * initData fixtures — they are NOT real BRUH membership proof and NOT real
 * Telegram signatures.
 */
import { randomUUID } from "node:crypto";
import { createEphemeralWrappingKey } from "../src/lib/custody/custody-vault.server";
import {
  HEADER_KEY_ID,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  bodyDigestHex,
  canonicalString,
  newNonce,
  signCanonical,
} from "../src/lib/custody/request-auth.server";
import { provisionDevnetWallet } from "../src/lib/wallets/provisioning.server";
import { publicView } from "../src/lib/wallets/wallet-store.server";
import { getDurableWalletStore } from "../src/lib/wallets/wallet-store.server";
import { getProductionMembershipAuthorizer } from "../src/lib/wallets/authorization.server";
import { getProductionWrappingVault } from "../src/lib/wallets/wrapping-key.server";
import { createInMemoryNonceStore } from "./support/in-memory-nonce-store";
import {
  buildFixtureInitData,
  createFailingWalletStore,
  createInMemoryWalletStore,
  failingAuthorizer,
  fixtureInitDataVerifier,
  generatedInitDataKeypair,
  mockAuthorizer,
  mockMismatchedAuthorizer,
} from "./support/wallet-fixtures";

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

const SECRET = "s".repeat(48);
const KEY_ID = "devnet-provisioning-test";
const PATH = "/internal/provisioning";
const NOW = 1_760_000_000_000;
const BOT_ID = "8763268934";
const USER_ID = 4242424242;
const CHAT_ID = "-1001234567890";

const vault = await createEphemeralWrappingKey("test-wrap-v1");
const fixtureKeys = generatedInitDataKeypair();
const verifyInitData = fixtureInitDataVerifier({
  botId: BOT_ID,
  publicKeyHex: fixtureKeys.publicKeyHex,
});

const initData = buildFixtureInitData({
  secret: fixtureKeys.secret,
  botId: BOT_ID,
  telegramUserId: USER_ID,
  authDateSeconds: Math.floor(NOW / 1000) - 5,
});

const approvalScope = { groupId: randomUUID(), membershipId: randomUUID() };

function body(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    telegram_init_data: initData,
    telegram_chat_id: CHAT_ID,
    ...overrides,
  });
}

function signedRequest(rawBody: string, nonce = newNonce(), timestamp = NOW) {
  const signature = signCanonical(
    SECRET,
    canonicalString({
      keyId: KEY_ID,
      method: "POST",
      path: PATH,
      timestamp: String(timestamp),
      nonce,
      bodyDigestHex: bodyDigestHex(rawBody),
    }),
  );
  return {
    method: "POST",
    path: PATH,
    rawBody,
    headers: new Headers({
      [HEADER_KEY_ID]: KEY_ID,
      [HEADER_TIMESTAMP]: String(timestamp),
      [HEADER_NONCE]: nonce,
      [HEADER_SIGNATURE]: signature,
    }),
  };
}

type Overrides = Partial<Parameters<typeof provisionDevnetWallet>[0]>;

function provision(store: ReturnType<typeof createInMemoryWalletStore>, overrides: Overrides = {}) {
  const nonces = createInMemoryNonceStore();
  const rawBody = (overrides.request?.rawBody as string | undefined) ?? body();
  return provisionDevnetWallet({
    enabled: true,
    request: signedRequest(rawBody),
    auth: { secret: SECRET, expectedKeyId: KEY_ID, consumeNonce: nonces.consume },
    authorizer: mockAuthorizer({ ...approvalScope, telegramChatId: CHAT_ID, telegramUserId: String(USER_ID) }),
    vault,
    store,
    now: NOW,
    verifyInitData,
    ...overrides,
  });
}

// ---------------------------------------------------------------- enable gate
{
  const store = createInMemoryWalletStore();
  const result = await provision(store, { enabled: false });
  check(
    "enable gate default-false rejects provisioning",
    !result.ok && result.reason === "provisioning_disabled",
  );
  check("nothing persisted while disabled", store.rows().length === 0);
}

// ------------------------------------------------------- production fail-closed
check("no production wrapping key configured (fail closed)", (await getProductionWrappingVault()) === null);
check("no production membership authorizer configured (fail closed)", (await getProductionMembershipAuthorizer()) === null);
check("no durable wallet store configured (fail closed)", (await getDurableWalletStore()) === null);

// ------------------------------------------------------------------ happy path
let firstAddress = "";
let firstWalletId = "";
{
  const store = createInMemoryWalletStore();
  const result = await provision(store);
  check("authenticated + verified + approved request provisions a wallet", result.ok === true);
  if (result.ok) {
    firstAddress = result.wallet.address;
    firstWalletId = result.wallet.walletId;
    check("wallet reported as created", result.created === true);
    check("network is strictly devnet", result.wallet.network === "devnet");
    check("account is frozen", result.wallet.frozen === true);
    check("key version comes from the server-side vault", result.wallet.wrappingKeyVersion === "test-wrap-v1");
    check("wallet id is a server-generated UUID", /^[0-9a-f-]{36}$/.test(result.wallet.walletId));
    check(
      "response exposes public metadata only (no envelope/seed/key fields)",
      Object.keys(result.wallet).sort().join(",") ===
        "address,frozen,network,walletId,wrappingKeyVersion",
    );
  }
  const row = store.rows()[0];
  check("exactly one row persisted", store.rows().length === 1);
  check("persisted scope is the approved scope", row?.scope.groupId === approvalScope.groupId && row?.scope.membershipId === approvalScope.membershipId);
  check("persisted scope binds telegram chat and user", row?.scope.telegramChatId === CHAT_ID && row?.scope.telegramUserId === String(USER_ID));
  check("persisted row is frozen", row?.frozen === true);
  check("persisted envelope is authenticated and scope-bound", row !== undefined && row.envelope.walletId === row.walletId && row.envelope.version === 1);
  check(
    "envelope round-trips under its own scope",
    await (async () => {
      if (!row) return false;
      try {
        await vault.validate(row.envelope, {
          walletId: row.walletId,
          groupId: row.scope.groupId,
          membershipId: row.scope.membershipId,
          network: "devnet",
        });
        return true;
      } catch {
        return false;
      }
    })(),
  );
  check(
    "envelope rejects a different wallet scope",
    await (async () => {
      if (!row) return false;
      try {
        await vault.validate(row.envelope, {
          walletId: randomUUID(),
          groupId: row.scope.groupId,
          membershipId: row.scope.membershipId,
          network: "devnet",
        });
        return false;
      } catch {
        return true;
      }
    })(),
  );
  check(
    "public view never carries the envelope",
    row !== undefined && !Object.keys(publicView(row)).includes("envelope"),
  );
}

// ------------------------------------------------------------- idempotence/race
{
  const store = createInMemoryWalletStore();
  const first = await provision(store);
  const second = await provision(store);
  check("repeat provisioning returns the same wallet", first.ok && second.ok && first.wallet.walletId === second.wallet.walletId);
  check("repeat provisioning reports created=false", second.ok === true && second.created === false);
  check("repeat provisioning does not overwrite the address", first.ok && second.ok && first.wallet.address === second.wallet.address);
  check("still exactly one persisted wallet for the scope", store.rows().length === 1);
}
{
  const store = createInMemoryWalletStore();
  const results = await Promise.all([provision(store), provision(store), provision(store), provision(store), provision(store), provision(store)]);
  const created = results.filter((r) => r.ok && r.created).length;
  const ids = new Set(results.map((r) => (r.ok ? r.wallet.walletId : "x")));
  check("6 concurrent attempts create exactly one wallet", created === 1);
  check("6 concurrent attempts all return the same wallet id", ids.size === 1);
  check("no orphaned second usable key persisted", store.rows().length === 1);
  check("addresses of losing attempts are never persisted", store.rows()[0]?.address === (results[0]?.ok ? results[0].wallet.address : ""));
}

// ------------------------------------------------------------------ auth denial
{
  const store = createInMemoryWalletStore();
  const nonces = createInMemoryNonceStore();
  const raw = body();
  const req = signedRequest(raw);

  const noSecret = await provisionDevnetWallet({
    enabled: true,
    request: req,
    auth: { secret: undefined, expectedKeyId: KEY_ID, consumeNonce: nonces.consume },
    authorizer: mockAuthorizer({ ...approvalScope, telegramChatId: CHAT_ID, telegramUserId: String(USER_ID) }),
    vault,
    store,
    now: NOW,
    verifyInitData,
  });
  check("missing caller secret rejects (unauthorized)", !noSecret.ok && noSecret.reason === "unauthorized");

  const noStore = await provisionDevnetWallet({
    enabled: true,
    request: req,
    auth: { secret: SECRET, expectedKeyId: KEY_ID, consumeNonce: null },
    authorizer: mockAuthorizer({ ...approvalScope, telegramChatId: CHAT_ID, telegramUserId: String(USER_ID) }),
    vault,
    store,
    now: NOW,
    verifyInitData,
  });
  check("missing durable nonce store rejects (unauthorized)", !noStore.ok && noStore.reason === "unauthorized");

  const stale = await provisionDevnetWallet({
    enabled: true,
    request: signedRequest(raw, newNonce(), NOW - 120_000),
    auth: { secret: SECRET, expectedKeyId: KEY_ID, consumeNonce: nonces.consume },
    authorizer: mockAuthorizer({ ...approvalScope, telegramChatId: CHAT_ID, telegramUserId: String(USER_ID) }),
    vault,
    store,
    now: NOW,
    verifyInitData,
  });
  check("stale HMAC timestamp rejects", !stale.ok && stale.reason === "unauthorized");

  const tampered = { ...req, rawBody: body({ telegram_chat_id: "-1009999999999" }) };
  const tamper = await provisionDevnetWallet({
    enabled: true,
    request: tampered,
    auth: { secret: SECRET, expectedKeyId: KEY_ID, consumeNonce: nonces.consume },
    authorizer: mockAuthorizer({ ...approvalScope, telegramChatId: CHAT_ID, telegramUserId: String(USER_ID) }),
    vault,
    store,
    now: NOW,
    verifyInitData,
  });
  check("body tampering breaks the digest binding", !tamper.ok && tamper.reason === "unauthorized");

  const nonce = newNonce();
  const replayReq = signedRequest(raw, nonce);
  const shared = createInMemoryNonceStore();
  const args = {
    enabled: true as const,
    request: replayReq,
    auth: { secret: SECRET, expectedKeyId: KEY_ID, consumeNonce: shared.consume },
    authorizer: mockAuthorizer({ ...approvalScope, telegramChatId: CHAT_ID, telegramUserId: String(USER_ID) }),
    vault,
    store: createInMemoryWalletStore(),
    now: NOW,
    verifyInitData,
  };
  const once = await provisionDevnetWallet(args);
  const twice = await provisionDevnetWallet(args);
  check("first signed provisioning request accepted", once.ok === true);
  check("byte-identical replay rejected by the one-time token", !twice.ok && twice.reason === "unauthorized");
  check("no wallet persisted by any denied request", store.rows().length === 0);
}

// --------------------------------------------------------------- initData gate
{
  const store = createInMemoryWalletStore();
  const productionVerifier = await provisionDevnetWallet({
    enabled: true,
    request: signedRequest(body()),
    auth: { secret: SECRET, expectedKeyId: KEY_ID, consumeNonce: createInMemoryNonceStore().consume },
    authorizer: mockAuthorizer({ ...approvalScope, telegramChatId: CHAT_ID, telegramUserId: String(USER_ID) }),
    vault,
    store,
    now: NOW,
  });
  check(
    "pinned production verifier rejects a generated-key fixture (default path)",
    !productionVerifier.ok && productionVerifier.reason === "initdata_rejected",
  );

  const wrongBot = fixtureInitDataVerifier({ botId: "1111111111", publicKeyHex: fixtureKeys.publicKeyHex });
  const botMismatch = await provision(store, { verifyInitData: wrongBot });
  check("wrong bot binding rejects", !botMismatch.ok && botMismatch.reason === "initdata_rejected");

  const wrongKey = fixtureInitDataVerifier({ botId: BOT_ID, publicKeyHex: generatedInitDataKeypair().publicKeyHex });
  const keyMismatch = await provision(store, { verifyInitData: wrongKey });
  check("wrong signing key rejects", !keyMismatch.ok && keyMismatch.reason === "initdata_rejected");

  const stale = buildFixtureInitData({
    secret: fixtureKeys.secret,
    botId: BOT_ID,
    telegramUserId: USER_ID,
    authDateSeconds: Math.floor(NOW / 1000) - 9_000,
  });
  const staleResult = await provision(store, {
    request: signedRequest(JSON.stringify({ telegram_init_data: stale, telegram_chat_id: CHAT_ID })),
  });
  check("stale initData rejects", !staleResult.ok && staleResult.reason === "initdata_rejected");
  check("nothing persisted by rejected sign-in payloads", store.rows().length === 0);
}

// ---------------------------------------------------------------- body contract
{
  const store = createInMemoryWalletStore();
  const cases: [string, string][] = [
    ["client-chosen wallet id rejected", body({ wallet_id: randomUUID() })],
    ["client-chosen key version rejected", body({ wrapping_key_version: "attacker-v9" })],
    ["client-supplied envelope rejected", body({ envelope: { encryptedSeed: "AA==" } })],
    ["client-supplied seed/key material rejected", body({ seed: "00".repeat(32) })],
    ["client-chosen group id rejected", body({ group_id: randomUUID() })],
    ["client-chosen network rejected", body({ network: "mainnet-beta" })],
    ["non-object body rejected", JSON.stringify([1, 2, 3])],
    ["invalid chat id rejected", JSON.stringify({ telegram_init_data: initData, telegram_chat_id: "not-a-chat" })],
    ["missing chat id rejected", JSON.stringify({ telegram_init_data: initData })],
  ];
  for (const [name, raw] of cases) {
    const result = await provision(store, { request: signedRequest(raw) });
    check(name, !result.ok && result.reason === "malformed_request");
  }
  check("nothing persisted by malformed bodies", store.rows().length === 0);
}

// ------------------------------------------------------ authorization callback
{
  const store = createInMemoryWalletStore();
  const missing = await provision(store, { authorizer: null });
  check("missing server-owned authorization callback rejects", !missing.ok && missing.reason === "authorization_unavailable");

  const broken = await provision(store, { authorizer: failingAuthorizer() });
  check("authorization source outage rejects (fail closed)", !broken.ok && broken.reason === "authorization_unavailable");

  const denied = await provision(store, { authorizer: mockAuthorizer(null) });
  check("unapproved member rejected", !denied.ok && denied.reason === "not_authorized_member");

  const wrongUser = await provision(store, {
    authorizer: mockMismatchedAuthorizer({
      approved: true,
      ...approvalScope,
      telegramChatId: CHAT_ID,
      telegramUserId: "9999999999",
    }),
  });
  check("approval for a different telegram user rejected", !wrongUser.ok && wrongUser.reason === "not_authorized_member");

  const wrongChat = await provision(store, {
    authorizer: mockMismatchedAuthorizer({
      approved: true,
      ...approvalScope,
      telegramChatId: "-1005555555555",
      telegramUserId: String(USER_ID),
    }),
  });
  check("approval for a different chat rejected", !wrongChat.ok && wrongChat.reason === "not_authorized_member");

  const badUuid = await provision(store, {
    authorizer: mockMismatchedAuthorizer({
      approved: true,
      groupId: "not-a-uuid",
      membershipId: approvalScope.membershipId,
      telegramChatId: CHAT_ID,
      telegramUserId: String(USER_ID),
    }),
  });
  check("malformed group UUID from the callback rejected", !badUuid.ok && badUuid.reason === "not_authorized_member");
  check("nothing persisted by unauthorized membership", store.rows().length === 0);
}

// ------------------------------------------------- scope separation / failures
{
  const store = createInMemoryWalletStore();
  await provision(store);

  // A different Telegram identity (different verified user) gets its own wallet.
  const otherUserId = 5555555555;
  const otherInitData = buildFixtureInitData({
    secret: fixtureKeys.secret,
    botId: BOT_ID,
    telegramUserId: otherUserId,
    authDateSeconds: Math.floor(NOW / 1000) - 5,
  });
  const otherRaw = JSON.stringify({
    telegram_init_data: otherInitData,
    telegram_chat_id: CHAT_ID,
  });
  const otherUser = await provisionDevnetWallet({
    enabled: true,
    request: signedRequest(otherRaw),
    auth: { secret: SECRET, expectedKeyId: KEY_ID, consumeNonce: createInMemoryNonceStore().consume },
    authorizer: mockAuthorizer({
      groupId: randomUUID(),
      membershipId: randomUUID(),
      telegramChatId: CHAT_ID,
      telegramUserId: String(otherUserId),
    }),
    vault,
    store,
    now: NOW,
    verifyInitData,
  });
  check("a different Telegram identity gets its own wallet", otherUser.ok === true && otherUser.created === true);
  check("two identities hold two distinct wallets", store.rows().length === 2);
  check(
    "distinct wallets hold distinct addresses",
    new Set(store.rows().map((r) => r.address)).size === 2,
  );

  // Same verified user, different approved UUID mapping: refused, not a 2nd wallet.
  const remapped = await provision(store, {
    authorizer: mockAuthorizer({
      groupId: randomUUID(),
      membershipId: randomUUID(),
      telegramChatId: CHAT_ID,
      telegramUserId: String(USER_ID),
    }),
  });
  check(
    "a changed group/membership mapping for the same user is refused",
    !remapped.ok && remapped.reason === "inconsistent_mapping",
  );
  check("no third wallet was created", store.rows().length === 2);


  const missingVault = await provision(store, { vault: null });
  check("missing wrapping key rejects, no invented key", !missingVault.ok && missingVault.reason === "wrapping_key_unavailable");
  const missingStore = await provision(store, { store: null });
  check("missing persistence rejects, no in-memory fallback", !missingStore.ok && missingStore.reason === "store_unavailable");
  const brokenStore = await provisionDevnetWallet({
    enabled: true,
    request: signedRequest(body()),
    auth: { secret: SECRET, expectedKeyId: KEY_ID, consumeNonce: createInMemoryNonceStore().consume },
    authorizer: mockAuthorizer({ ...approvalScope, telegramChatId: CHAT_ID, telegramUserId: String(USER_ID) }),
    vault,
    store: createFailingWalletStore(),
    now: NOW,
    verifyInitData,
  });
  check("store outage rejects (fail closed)", !brokenStore.ok && brokenStore.reason === "store_error");
}

check("first provisioned address stayed a bs58 devnet address", /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(firstAddress));
check("first provisioned wallet id was a UUID", /^[0-9a-f-]{36}$/.test(firstWalletId));

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
