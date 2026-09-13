/**
 * Strict stored-record validation tests (offline, source-only).
 *
 * Covers: exact envelope structure, canonical base64 and decoded lengths,
 * envelope↔row bindings, scope equality, and the provisioning service's refusal
 * to trust anything a store returns (found row, winning row, mapping row).
 *
 * No database, no network, no funding, no real Telegram proof. Synthetic
 * envelope fixtures are random padding, never real keys or ciphertexts.
 */
import { randomUUID } from "node:crypto";
import bs58 from "bs58";
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
import {
  InvalidWalletRecord,
  parseCustodyEnvelope,
  parseWalletRecord,
} from "../src/lib/wallets/wallet-record.server";
import { publicView, type WalletScope } from "../src/lib/wallets/wallet-store.server";
import { provisionDevnetWallet } from "../src/lib/wallets/provisioning.server";
import { createInMemoryNonceStore } from "./support/in-memory-nonce-store";
import {
  buildFixtureInitData,
  createInMemoryWalletStore,
  createRowInjectingWalletStore,
  fixtureInitDataVerifier,
  generatedInitDataKeypair,
  mockAuthorizer,
  syntheticEnvelopeFixture,
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
function rejects(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (error) {
    return error instanceof InvalidWalletRecord;
  }
}

const vault = await createEphemeralWrappingKey("record-test-v1");
const scope: WalletScope = {
  groupId: randomUUID(),
  membershipId: randomUUID(),
  telegramChatId: "-1001234567890",
  telegramUserId: "4242424242",
  network: "devnet",
};
const walletId = randomUUID();
const envelope = await vault.provision({
  walletId,
  groupId: scope.groupId,
  membershipId: scope.membershipId,
  network: "devnet",
});
const record = {
  walletId,
  scope,
  address: envelope.address,
  wrappingKeyVersion: envelope.wrappingKeyVersion,
  frozen: true as const,
  envelope,
};

// ------------------------------------------------------------- envelope parsing
check("a real vault envelope parses", parseCustodyEnvelope(envelope).walletId === walletId);
check("a structurally synthetic envelope fixture parses", (() => {
  const synthetic = syntheticEnvelopeFixture({
    walletId,
    groupId: scope.groupId,
    membershipId: scope.membershipId,
    address: envelope.address,
    wrappingKeyVersion: "wrap-v1",
  });
  return parseCustodyEnvelope(synthetic).wrappingKeyVersion === "wrap-v1";
})());
check("empty object envelope rejected", rejects(() => parseCustodyEnvelope({})));
check("null envelope rejected", rejects(() => parseCustodyEnvelope(null)));
check("array envelope rejected", rejects(() => parseCustodyEnvelope([envelope])));
check("string envelope rejected", rejects(() => parseCustodyEnvelope(JSON.stringify(envelope))));
check("extra envelope field rejected", rejects(() => parseCustodyEnvelope({ ...envelope, extra: 1 })));
for (const key of Object.keys(envelope)) {
  const partial: Record<string, unknown> = { ...envelope };
  delete partial[key];
  check(`missing envelope field ${key} rejected`, rejects(() => parseCustodyEnvelope(partial)));
  check(`null envelope field ${key} rejected`, rejects(() => parseCustodyEnvelope({ ...envelope, [key]: null })));
}
check("wrong envelope version rejected", rejects(() => parseCustodyEnvelope({ ...envelope, version: 2 })));
check("string version rejected", rejects(() => parseCustodyEnvelope({ ...envelope, version: "1" })));
check("non-devnet envelope network rejected", rejects(() => parseCustodyEnvelope({ ...envelope, network: "mainnet-beta" })));
check("non-uuid wallet id rejected", rejects(() => parseCustodyEnvelope({ ...envelope, walletId: "abc" })));
check("bad key version rejected", rejects(() => parseCustodyEnvelope({ ...envelope, wrappingKeyVersion: "bad version!" })));
check("non-base58 address rejected", rejects(() => parseCustodyEnvelope({ ...envelope, address: "0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl" })));
check(
  "address with wrong decoded length rejected",
  rejects(() => parseCustodyEnvelope({ ...envelope, address: bs58.encode(new Uint8Array(31)) })),
);
check(
  "short IV rejected",
  rejects(() => parseCustodyEnvelope({ ...envelope, seedIv: Buffer.alloc(11).toString("base64") })),
);
check(
  "long IV rejected",
  rejects(() => parseCustodyEnvelope({ ...envelope, wrappingIv: Buffer.alloc(16).toString("base64") })),
);
check(
  "wrong ciphertext length rejected (32 bytes, no tag)",
  rejects(() => parseCustodyEnvelope({ ...envelope, encryptedSeed: Buffer.alloc(32).toString("base64") })),
);
check(
  "wrong wrapped key length rejected",
  rejects(() => parseCustodyEnvelope({ ...envelope, wrappedDataKey: Buffer.alloc(47).toString("base64") })),
);
check(
  "non-canonical base64 rejected",
  rejects(() => parseCustodyEnvelope({ ...envelope, seedIv: `${envelope.seedIv.slice(0, -1)}A` })),
);
check(
  "base64url alphabet rejected",
  rejects(() => parseCustodyEnvelope({ ...envelope, wrappedDataKey: Buffer.from(new Uint8Array(48)).toString("base64url") + "==" })),
);
check(
  "whitespace in base64 rejected",
  rejects(() => parseCustodyEnvelope({ ...envelope, seedIv: ` ${envelope.seedIv}` })),
);

// --------------------------------------------------------------- record parsing
check("a well-formed record parses", parseWalletRecord(record, scope).walletId === walletId);
check("extra record field rejected", rejects(() => parseWalletRecord({ ...record, foo: 1 }, scope)));
check("missing record field rejected", rejects(() => parseWalletRecord({ walletId, scope, address: record.address, frozen: true, envelope }, scope)));
check("frozen=false record rejected", rejects(() => parseWalletRecord({ ...record, frozen: false }, scope)));
check("non-boolean frozen rejected", rejects(() => parseWalletRecord({ ...record, frozen: "true" }, scope)));
check("non-uuid record wallet id rejected", rejects(() => parseWalletRecord({ ...record, walletId: "nope" }, scope)));
check("bad record key version rejected", rejects(() => parseWalletRecord({ ...record, wrappingKeyVersion: "!" }, scope)));
check("bad record address rejected", rejects(() => parseWalletRecord({ ...record, address: "0OIl" }, scope)));
check("extra scope field rejected", rejects(() => parseWalletRecord({ ...record, scope: { ...scope, extra: 1 } }, scope)));
check("non-devnet scope network rejected", rejects(() => parseWalletRecord({ ...record, scope: { ...scope, network: "mainnet-beta" } }, scope)));
for (const key of ["groupId", "membershipId", "telegramChatId", "telegramUserId"] as const) {
  const changed = { ...scope, [key]: key.startsWith("telegram") ? "1" : randomUUID() };
  check(
    `record for a different ${key} rejected`,
    rejects(() => parseWalletRecord({ ...record, scope: changed }, scope)),
  );
}
check(
  "row carrying another wallet's envelope rejected",
  rejects(() =>
    parseWalletRecord(
      { ...record, envelope: { ...envelope, walletId: randomUUID() } },
      scope,
    ),
  ),
);
check(
  "row whose address disagrees with the envelope rejected",
  rejects(() =>
    parseWalletRecord({ ...record, address: bs58.encode(new Uint8Array(32).fill(7)) }, scope),
  ),
);
check(
  "row whose key version disagrees with the envelope rejected",
  rejects(() => parseWalletRecord({ ...record, wrappingKeyVersion: "other-v9" }, scope)),
);
check(
  "envelope bound to a different group rejected",
  rejects(() =>
    parseWalletRecord({ ...record, envelope: { ...envelope, groupId: randomUUID() } }, scope),
  ),
);

// ------------------------------------------------------------------- publicView
check("publicView projects a validated record", publicView(record).network === "devnet");
check(
  "publicView refuses an unfrozen record instead of hardcoding frozen",
  (() => {
    try {
      publicView({ ...record, frozen: false as unknown as true });
      return false;
    } catch {
      return true;
    }
  })(),
);
check(
  "publicView refuses a non-devnet record instead of hardcoding devnet",
  (() => {
    try {
      publicView({
        ...record,
        scope: { ...scope, network: "mainnet-beta" as unknown as "devnet" },
      });
      return false;
    } catch {
      return true;
    }
  })(),
);

// ------------------------------------------------- service distrusts the store
const SECRET = "s".repeat(48);
const KEY_ID = "record-test-key";
const PATH = "/internal/provisioning";
const NOW = 1_760_000_000_000;
const BOT_ID = "8763268934";
const USER_ID = Number(scope.telegramUserId);
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
const rawBody = JSON.stringify({
  telegram_init_data: initData,
  telegram_chat_id: scope.telegramChatId,
});

function request(method = "POST") {
  const nonce = newNonce();
  const signature = signCanonical(
    SECRET,
    canonicalString({
      keyId: KEY_ID,
      method,
      path: PATH,
      timestamp: String(NOW),
      nonce,
      bodyDigestHex: bodyDigestHex(rawBody),
    }),
  );
  return {
    method,
    path: PATH,
    rawBody,
    headers: new Headers({
      [HEADER_KEY_ID]: KEY_ID,
      [HEADER_TIMESTAMP]: String(NOW),
      [HEADER_NONCE]: nonce,
      [HEADER_SIGNATURE]: signature,
    }),
  };
}

function call(store: Parameters<typeof provisionDevnetWallet>[0]["store"], method = "POST") {
  return provisionDevnetWallet({
    enabled: true,
    request: request(method),
    auth: {
      secret: SECRET,
      expectedKeyId: KEY_ID,
      consumeNonce: createInMemoryNonceStore().consume,
    },
    authorizer: mockAuthorizer({
      groupId: scope.groupId,
      membershipId: scope.membershipId,
      telegramChatId: scope.telegramChatId,
      telegramUserId: scope.telegramUserId,
    }),
    vault,
    store,
    now: NOW,
    verifyInitData,
  });
}

for (const method of ["GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "post"]) {
  const result = await call(createInMemoryWalletStore(), method);
  check(`${method} is refused; provisioning is POST-only`, !result.ok && result.reason === "method_not_allowed");
}

const badFound: [string, unknown][] = [
  ["malformed found row rejected", { walletId, scope, address: record.address }],
  ["found row with empty envelope rejected", { ...record, envelope: {} }],
  ["found row for another wallet's envelope rejected", { ...record, envelope: { ...envelope, walletId: randomUUID() } }],
  ["found row with a foreign scope rejected", { ...record, scope: { ...scope, groupId: randomUUID() } }],
  ["found row with extra fields rejected", { ...record, isAdmin: true }],
  ["unfrozen found row rejected", { ...record, frozen: false }],
];
for (const [name, row] of badFound) {
  const result = await call(createRowInjectingWalletStore({ find: row }));
  check(name, !result.ok && result.reason === "store_record_invalid");
}
{
  const good = await call(createRowInjectingWalletStore({ find: record }));
  check("a valid found row is returned as created=false", good.ok === true && good.created === false);
}
const badWinner: [string, unknown][] = [
  ["malformed winning row rejected", { ...record, envelope: { ...envelope, seedIv: "AA==" } }],
  ["winning row for a different scope rejected", { ...record, scope: { ...scope, membershipId: randomUUID() } }],
  ["winning row with no envelope rejected", { ...record, envelope: null }],
];
for (const [name, row] of badWinner) {
  const result = await call(createRowInjectingWalletStore({ insert: row }));
  check(name, !result.ok && result.reason === "store_record_invalid");
}
{
  const nonBoolean = await call(
    createRowInjectingWalletStore({ created: undefined as unknown as boolean, insert: record }),
  );
  check("non-true created flag is treated as not-created", nonBoolean.ok === true && nonBoolean.created === true);
}

// --------------------------------------------- one wallet per Telegram identity
{
  const remapped = await call(
    createRowInjectingWalletStore({
      identity: {
        walletId: randomUUID(),
        scope: { ...scope, groupId: randomUUID(), membershipId: randomUUID() },
      },
    }),
  );
  check(
    "same Telegram identity under a new UUID mapping is refused",
    !remapped.ok && remapped.reason === "inconsistent_mapping",
  );
}
{
  const groupOnly = await call(
    createRowInjectingWalletStore({
      identity: { walletId: randomUUID(), scope: { ...scope, membershipId: randomUUID() } },
    }),
  );
  check(
    "same identity with a new membership UUID is refused",
    !groupOnly.ok && groupOnly.reason === "inconsistent_mapping",
  );
}
{
  const contradictory = await call(
    createRowInjectingWalletStore({ find: null, identity: { walletId, scope } }),
  );
  check(
    "store contradicting itself (identity row but no scope row) fails closed",
    !contradictory.ok && contradictory.reason === "store_record_invalid",
  );
}
{
  const store = createInMemoryWalletStore();
  const first = await call(store);
  check("first provisioning through the in-memory store succeeds", first.ok === true);
  const remap = await provisionDevnetWallet({
    enabled: true,
    request: request(),
    auth: {
      secret: SECRET,
      expectedKeyId: KEY_ID,
      consumeNonce: createInMemoryNonceStore().consume,
    },
    // Same verified Telegram user and chat, different approved UUID mapping.
    authorizer: mockAuthorizer({
      groupId: randomUUID(),
      membershipId: randomUUID(),
      telegramChatId: scope.telegramChatId,
      telegramUserId: scope.telegramUserId,
    }),
    vault,
    store,
    now: NOW,
    verifyInitData,
  });
  check(
    "a changed UUID mapping cannot mint a second wallet for the same user",
    !remap.ok && remap.reason === "inconsistent_mapping",
  );
  check("still exactly one persisted wallet", store.rows().length === 1);
}

console.log(`\n${pass} passed, ${fail} failed`);
console.log(
  "NOTE: synthetic envelope fixtures are random padding, not real keys or ciphertexts; membership approvals are mocks, not real BRUH proof.",
);
if (fail > 0) process.exit(1);
