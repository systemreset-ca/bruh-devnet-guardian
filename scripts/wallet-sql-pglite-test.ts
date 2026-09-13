/**
 * ACTUAL isolated PostgreSQL checks for the PROPOSED wallet envelope schema.
 *
 * Runs docs/proposed-migration-wallets.sql verbatim inside an in-process PGlite
 * database. Nothing here touches the project's Cloud backend: the proposal is
 * NOT applied there. Output is names, booleans and counts only.
 *
 * Envelope fixtures are structurally realistic SYNTHETIC values (correct key
 * set, canonical base64, 12-byte IVs, 48-byte AES-GCM outputs, base58 32-byte
 * address) built from random padding. They are NOT real keys and NOT real
 * ciphertexts, and nothing can decrypt them.
 *
 * Concurrency note: PGlite exposes a single session, so same-scope repeat
 * attempts below are SEQUENTIAL, not real multi-session concurrency. Real
 * parallel behaviour must be re-measured after the migration is applied.
 */
import { readFileSync } from "node:fs";
import { randomUUID, webcrypto } from "node:crypto";
import bs58 from "bs58";
import { PGlite } from "@electric-sql/pglite";
import { createRpcWalletStore } from "../src/lib/wallets/wallet-store.server";
import { syntheticEnvelopeFixture } from "./support/wallet-fixtures";

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

const db = new PGlite();
// API roles do not exist in a bare PostgreSQL; create them so grant assertions
// mirror the managed backend.
await db.exec(`
  CREATE ROLE anon NOLOGIN;
  CREATE ROLE authenticated NOLOGIN;
  CREATE ROLE service_role NOLOGIN;
`);
await db.exec(readFileSync("docs/proposed-migration-wallets.sql", "utf8"));
check("proposed migration applies cleanly on an isolated PostgreSQL", true);

const KEY_VERSION = "wrap-v1";
const scope = {
  group: randomUUID(),
  membership: randomUUID(),
  chat: "-1001234567890",
  user: "4242424242",
};
const syntheticAddress = () => bs58.encode(webcrypto.getRandomValues(new Uint8Array(32)));

function envelopeFor(walletId: string, address: string, overrides: Record<string, unknown> = {}, ids = scope) {
  return {
    ...syntheticEnvelopeFixture({
      walletId,
      groupId: ids.group,
      membershipId: ids.membership,
      address,
      wrappingKeyVersion: KEY_VERSION,
    }),
    ...overrides,
  };
}

async function provision(
  walletId: string,
  address: string,
  options: { ids?: typeof scope; envelope?: unknown } = {},
) {
  const ids = options.ids ?? scope;
  const envelope = options.envelope ?? envelopeFor(walletId, address, {}, ids);
  const result = await db.query<{ wallet_id: string; address: string; created: boolean }>(
    `SELECT * FROM public.provision_devnet_wallet($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
    [walletId, ids.group, ids.membership, ids.chat, ids.user, KEY_VERSION, address, JSON.stringify(envelope)],
  );
  return result.rows[0]!;
}

async function rejects(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

const WALLET_A = randomUUID();
const ADDRESS_A = syntheticAddress();

const first = await provision(WALLET_A, ADDRESS_A);
check("first provisioning inserts and reports created=true", first.created === true);
check("returned wallet id is the server-supplied UUID", first.wallet_id === WALLET_A);

const second = await provision(randomUUID(), syntheticAddress());
check("sequential repeat for the same scope reports created=false", second.created === false);
check("repeat returns the already persisted wallet id", second.wallet_id === WALLET_A);
check("repeat never overwrites the address", second.address === ADDRESS_A);

const count = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM public.devnet_wallets`);
check("exactly one row per scope", count.rows[0]?.n === 1);

const stored = await db.query<{ network: string; frozen: boolean; telegram_chat_id: string; telegram_user_id: string }>(
  `SELECT network, frozen, telegram_chat_id, telegram_user_id FROM public.devnet_wallets WHERE wallet_id = $1`,
  [WALLET_A],
);
check("network is stored as devnet", stored.rows[0]?.network === "devnet");
check("account is stored frozen", stored.rows[0]?.frozen === true);
check(
  "scope binds telegram chat id and user id",
  stored.rows[0]?.telegram_chat_id === scope.chat && stored.rows[0]?.telegram_user_id === scope.user,
);

// ---------------------------------------------------- audit event (same txn)
const audit = await db.query<{ n: number; event_type: string; wallet_id: string }>(
  `SELECT count(*) OVER ()::int AS n, event_type, wallet_id FROM public.devnet_wallet_events`,
);
check("wallet creation wrote exactly one audit event", audit.rows.length === 1);
check("audit event type is wallet_created", audit.rows[0]?.event_type === "wallet_created");
check("audit event references the created wallet", audit.rows[0]?.wallet_id === WALLET_A);
const auditColumns = await db.query<{ column_name: string }>(
  `SELECT column_name FROM information_schema.columns WHERE table_name = 'devnet_wallet_events'`,
);
check(
  "audit table has no envelope column",
  !auditColumns.rows.some((r) => r.column_name === "envelope"),
);
check("repeat provisioning wrote no second audit event", (
  await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM public.devnet_wallet_events`)
).rows[0]?.n === 1);
check(
  "audit rows cannot be updated",
  await rejects(() => db.query(`UPDATE public.devnet_wallet_events SET event_type = 'wallet_created'`)),
);
check(
  "audit rows cannot be deleted",
  await rejects(() => db.query(`DELETE FROM public.devnet_wallet_events`)),
);
check(
  "a wallet row cannot be deleted while its audit event references it",
  await rejects(() => db.query(`DELETE FROM public.devnet_wallets WHERE wallet_id = $1`, [WALLET_A])),
);
check(
  "an audit event for an unknown wallet is rejected",
  await rejects(() =>
    db.query(
      `INSERT INTO public.devnet_wallet_events (wallet_id, event_type, group_id, membership_id, telegram_chat_id, telegram_user_id, network, address, wrapping_key_version)
       VALUES ($1,'wallet_created',$2,$3,$4,$5,'devnet',$6,$7)`,
      [randomUUID(), scope.group, scope.membership, scope.chat, scope.user, syntheticAddress(), KEY_VERSION],
    ),
  ),
);

// ------------------------------------- one wallet per Telegram identity (item 3)
check(
  "same Telegram identity with a different group UUID is refused",
  await rejects(() =>
    provision(randomUUID(), syntheticAddress(), { ids: { ...scope, group: randomUUID() } }),
  ),
);
check(
  "same Telegram identity with a different membership UUID is refused",
  await rejects(() =>
    provision(randomUUID(), syntheticAddress(), { ids: { ...scope, membership: randomUUID() } }),
  ),
);
check(
  "same identity with both UUIDs changed is refused",
  await rejects(() =>
    provision(randomUUID(), syntheticAddress(), {
      ids: { ...scope, group: randomUUID(), membership: randomUUID() },
    }),
  ),
);
check("remapping attempts created no extra wallet", (
  await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM public.devnet_wallets`)
).rows[0]?.n === 1);
check(
  "direct insert bypassing the routine still hits the identity unique constraint",
  await rejects(() => {
    const walletId = randomUUID();
    const address = syntheticAddress();
    return db.query(
      `INSERT INTO public.devnet_wallets (wallet_id, group_id, membership_id, telegram_chat_id, telegram_user_id, wrapping_key_version, address, envelope)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
      [
        walletId,
        randomUUID(),
        randomUUID(),
        scope.chat,
        scope.user,
        KEY_VERSION,
        address,
        JSON.stringify(
          syntheticEnvelopeFixture({
            walletId,
            groupId: scope.group,
            membershipId: scope.membership,
            address,
            wrappingKeyVersion: KEY_VERSION,
          }),
        ),
      ],
    );
  }),
);

// A different Telegram identity does get its own wallet.
const otherIds = { group: randomUUID(), membership: randomUUID(), chat: scope.chat, user: "5555555555" };
const otherWallet = randomUUID();
const otherAddress = syntheticAddress();
const other = await provision(otherWallet, otherAddress, { ids: otherIds });
check("a different Telegram identity gets its own wallet", other.created === true);
check("two identities, two audit events", (
  await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM public.devnet_wallet_events`)
).rows[0]?.n === 2);

check(
  "duplicate address for a new identity rejected",
  await rejects(() =>
    provision(randomUUID(), ADDRESS_A, { ids: { group: randomUUID(), membership: randomUUID(), chat: scope.chat, user: "6666666666" } }),
  ),
);

// --------------------------------------------- envelope structure (item 2)
const walletC = randomUUID();
const addressC = syntheticAddress();
const idsC = { group: randomUUID(), membership: randomUUID(), chat: scope.chat, user: "7777777777" };
const goodC = envelopeFor(walletC, addressC, {}, idsC);
const badEnvelopes: [string, unknown][] = [
  ["empty object envelope rejected", {}],
  ["null envelope rejected", null],
  ["json array envelope rejected", [goodC]],
  ["json string envelope rejected", "envelope"],
  ["extra envelope key rejected", { ...goodC, extra: 1 }],
  ["missing envelope key rejected", (() => { const e: Record<string, unknown> = { ...goodC }; delete e["seedIv"]; return e; })()],
  ["null envelope field rejected", { ...goodC, wrappedDataKey: null }],
  ["wrong version rejected", { ...goodC, version: 2 }],
  ["string version rejected", { ...goodC, version: "1" }],
  ["non-devnet envelope network rejected", { ...goodC, network: "mainnet-beta" }],
  ["envelope wallet id mismatch rejected", { ...goodC, walletId: randomUUID() }],
  ["envelope group mismatch rejected", { ...goodC, groupId: randomUUID() }],
  ["envelope membership mismatch rejected", { ...goodC, membershipId: randomUUID() }],
  ["envelope address mismatch rejected", { ...goodC, address: syntheticAddress() }],
  ["envelope key version mismatch rejected", { ...goodC, wrappingKeyVersion: "other-v9" }],
  ["short IV rejected", { ...goodC, seedIv: Buffer.alloc(11).toString("base64") }],
  ["long IV rejected", { ...goodC, wrappingIv: Buffer.alloc(16).toString("base64") }],
  ["ciphertext without GCM tag rejected", { ...goodC, encryptedSeed: Buffer.alloc(32).toString("base64") }],
  ["wrapped key of wrong length rejected", { ...goodC, wrappedDataKey: Buffer.alloc(47).toString("base64") }],
  ["non-canonical base64 rejected", { ...goodC, seedIv: `${goodC.seedIv}=` }],
  ["base64url alphabet rejected", { ...goodC, wrappingIv: Buffer.alloc(12).toString("base64url").replace(/A/g, "-") }],
  ["numeric base64 field rejected", { ...goodC, seedIv: 12 }],
];
for (const [name, envelope] of badEnvelopes) {
  check(
    name,
    await rejects(() => provision(walletC, addressC, { ids: idsC, envelope })),
  );
}
check("no wallet was created by any malformed envelope", (
  await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM public.devnet_wallets`)
).rows[0]?.n === 2);
const goodProvision = await provision(walletC, addressC, { ids: idsC, envelope: goodC });
check("a structurally valid synthetic envelope is accepted", goodProvision.created === true);

// ------------------------------------------------------------ input constraints
const badInputs: [string, unknown[]][] = [
  ["invalid chat id rejected", [randomUUID(), randomUUID(), randomUUID(), "abc", "1", KEY_VERSION]],
  ["invalid user id rejected", [randomUUID(), randomUUID(), randomUUID(), scope.chat, "-5", KEY_VERSION]],
  ["invalid key version rejected", [randomUUID(), randomUUID(), randomUUID(), scope.chat, "8888888888", "bad version!"]],
  ["null wallet id rejected", [null, randomUUID(), randomUUID(), scope.chat, "8888888888", KEY_VERSION]],
];
for (const [name, params] of badInputs) {
  const walletId = (params[0] ?? randomUUID()) as string;
  const address = syntheticAddress();
  check(
    name,
    await rejects(() =>
      db.query(`SELECT * FROM public.provision_devnet_wallet($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, [
        params[0],
        params[1],
        params[2],
        params[3],
        params[4],
        params[5],
        address,
        JSON.stringify(
          syntheticEnvelopeFixture({
            walletId,
            groupId: params[1] as string,
            membershipId: params[2] as string,
            address,
            wrappingKeyVersion: KEY_VERSION,
          }),
        ),
      ]),
    ),
  );
}
check(
  "invalid address rejected",
  await rejects(() =>
    provision(randomUUID(), "0OIl-not-base58", {
      ids: { group: randomUUID(), membership: randomUUID(), chat: scope.chat, user: "9999999999" },
      envelope: goodC,
    }),
  ),
);
check(
  "non-devnet network rejected by the check constraint",
  await rejects(() => {
    const walletId = randomUUID();
    const address = syntheticAddress();
    const ids = { group: randomUUID(), membership: randomUUID() };
    return db.query(
      `INSERT INTO public.devnet_wallets (wallet_id, group_id, membership_id, telegram_chat_id, telegram_user_id, network, wrapping_key_version, address, envelope)
       VALUES ($1,$2,$3,$4,$5,'mainnet-beta',$6,$7,$8::jsonb)`,
      [walletId, ids.group, ids.membership, scope.chat, "1010101010", KEY_VERSION, address,
        JSON.stringify(syntheticEnvelopeFixture({ walletId, groupId: ids.group, membershipId: ids.membership, address, wrappingKeyVersion: KEY_VERSION }))],
    );
  }),
);
check(
  "unfrozen account rejected by the check constraint",
  await rejects(() => {
    const walletId = randomUUID();
    const address = syntheticAddress();
    const ids = { group: randomUUID(), membership: randomUUID() };
    return db.query(
      `INSERT INTO public.devnet_wallets (wallet_id, group_id, membership_id, telegram_chat_id, telegram_user_id, wrapping_key_version, address, envelope, frozen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,false)`,
      [walletId, ids.group, ids.membership, scope.chat, "1111111111", KEY_VERSION, address,
        JSON.stringify(syntheticEnvelopeFixture({ walletId, groupId: ids.group, membershipId: ids.membership, address, wrappingKeyVersion: KEY_VERSION }))],
    );
  }),
);

// ------------------------------------------------------------------ immutability
for (const [name, column, value] of [
  ["wallet id immutable", "wallet_id", `'${randomUUID()}'`],
  ["group id immutable", "group_id", `'${randomUUID()}'`],
  ["membership id immutable", "membership_id", `'${randomUUID()}'`],
  ["telegram chat id immutable", "telegram_chat_id", "'-100999'"],
  ["telegram user id immutable", "telegram_user_id", "'1'"],
  ["key version immutable", "wrapping_key_version", "'wrap-v2'"],
  ["address immutable", "address", `'${syntheticAddress()}'`],
  ["frozen immutable", "frozen", "false"],
  ["envelope immutable (no replacement, no rotation)", "envelope", `'${JSON.stringify(envelopeFor(WALLET_A, ADDRESS_A))}'::jsonb`],
  ["created_at immutable", "created_at", "now() - interval '1 day'"],
] as const) {
  check(
    name,
    await rejects(() =>
      db.query(`UPDATE public.devnet_wallets SET ${column} = ${value} WHERE wallet_id = $1`, [WALLET_A]),
    ),
  );
}

// ------------------------------------------------------------------ read routines
const scopedRead = await db.query<Record<string, unknown>>(
  `SELECT * FROM public.read_devnet_wallet_scoped($1,$2,$3,$4)`,
  [scope.group, scope.membership, scope.chat, scope.user],
);
check(
  "scoped read returns metadata only, no envelope column",
  Object.keys(scopedRead.rows[0] ?? {}).sort().join(",") === "address,frozen,wallet_id,wrapping_key_version",
);
check("scoped read returns the persisted address", scopedRead.rows[0]?.["address"] === ADDRESS_A);
check(
  "scoped read with a wrong membership returns nothing",
  (await db.query(`SELECT * FROM public.read_devnet_wallet_scoped($1,$2,$3,$4)`, [scope.group, randomUUID(), scope.chat, scope.user])).rows.length === 0,
);

const mapping = await db.query<Record<string, unknown>>(
  `SELECT * FROM public.read_devnet_wallet_by_telegram($1,$2)`,
  [scope.chat, scope.user],
);
check(
  "telegram mapping read returns ids only, no address and no envelope",
  Object.keys(mapping.rows[0] ?? {}).sort().join(",") ===
    "group_id,membership_id,telegram_chat_id,telegram_user_id,wallet_id",
);

// ------------------------------------------------- fully scoped envelope read (4)
const envRead = await db.query<{ envelope: unknown }>(
  `SELECT * FROM public.read_devnet_wallet_envelope($1,$2,$3,$4,$5)`,
  [WALLET_A, scope.group, scope.membership, scope.chat, scope.user],
);
check("fully scoped envelope read returns the envelope", typeof envRead.rows[0]?.envelope === "object");
check(
  "no wallet-id-only envelope read exists",
  (await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_proc WHERE proname = 'read_devnet_wallet_envelope' AND pronargs <> 5`,
  )).rows[0]?.n === 0,
);
for (const [name, params] of [
  ["envelope read with a wrong group returns nothing", [WALLET_A, randomUUID(), scope.membership, scope.chat, scope.user]],
  ["envelope read with a wrong membership returns nothing", [WALLET_A, scope.group, randomUUID(), scope.chat, scope.user]],
  ["envelope read with a wrong chat returns nothing", [WALLET_A, scope.group, scope.membership, "-100999", scope.user]],
  ["envelope read with a wrong user returns nothing", [WALLET_A, scope.group, scope.membership, scope.chat, "1234567890"]],
  ["envelope read for another wallet's id returns nothing", [otherWallet, scope.group, scope.membership, scope.chat, scope.user]],
] as const) {
  const rows = await db.query(
    `SELECT * FROM public.read_devnet_wallet_envelope($1,$2,$3,$4,$5)`,
    params as unknown[],
  );
  check(name, rows.rows.length === 0);
}

// ------------------------------------ controlled-RPC adapter against this schema
const rpcStore = createRpcWalletStore(async (routine, params) => {
  const order: Record<string, string[]> = {
    provision_devnet_wallet: [
      "p_wallet_id", "p_group_id", "p_membership_id", "p_telegram_chat_id",
      "p_telegram_user_id", "p_wrapping_key_version", "p_address", "p_envelope",
    ],
    read_devnet_wallet_scoped: ["p_group_id", "p_membership_id", "p_telegram_chat_id", "p_telegram_user_id"],
    read_devnet_wallet_by_telegram: ["p_telegram_chat_id", "p_telegram_user_id"],
    read_devnet_wallet_envelope: [
      "p_wallet_id", "p_group_id", "p_membership_id", "p_telegram_chat_id", "p_telegram_user_id",
    ],
  };
  const names = order[routine]!;
  const values = names.map((name) => {
    const value = params[name];
    return name === "p_envelope" ? JSON.stringify(value) : value;
  });
  const placeholders = names
    .map((name, index) => (name === "p_envelope" ? `$${index + 1}::jsonb` : `$${index + 1}`))
    .join(",");
  const result = await db.query(`SELECT * FROM public.${routine}(${placeholders})`, values);
  return result.rows;
});

const rpcScope = {
  groupId: randomUUID(),
  membershipId: randomUUID(),
  telegramChatId: scope.chat,
  telegramUserId: "1212121212",
  network: "devnet" as const,
};
check("adapter finds nothing for an unprovisioned scope", (await rpcStore.findByScope(rpcScope)) === null);
check(
  "adapter finds no telegram mapping for an unprovisioned identity",
  (await rpcStore.findByTelegramIdentity({
    telegramChatId: rpcScope.telegramChatId,
    telegramUserId: rpcScope.telegramUserId,
    network: "devnet",
  })) === null,
);
const rpcWalletId = randomUUID();
const rpcAddress = syntheticAddress();
const rpcCandidate = {
  walletId: rpcWalletId,
  scope: rpcScope,
  address: rpcAddress,
  wrappingKeyVersion: KEY_VERSION,
  frozen: true as const,
  envelope: syntheticEnvelopeFixture({
    walletId: rpcWalletId,
    groupId: rpcScope.groupId,
    membershipId: rpcScope.membershipId,
    address: rpcAddress,
    wrappingKeyVersion: KEY_VERSION,
  }),
};
const inserted = await rpcStore.insertIfAbsent(rpcCandidate);
check("adapter insert reports created=true and a validated record", inserted.created === true && inserted.record.walletId === rpcWalletId);
check("adapter re-read validates the persisted record", (await rpcStore.findByScope(rpcScope))?.address === rpcAddress);
const repeat = await rpcStore.insertIfAbsent({ ...rpcCandidate, walletId: randomUUID() });
check("adapter repeat insert reports created=false with the original wallet id", repeat.created === false && repeat.record.walletId === rpcWalletId);
check(
  "adapter reports the telegram mapping for a provisioned identity",
  (await rpcStore.findByTelegramIdentity({
    telegramChatId: rpcScope.telegramChatId,
    telegramUserId: rpcScope.telegramUserId,
    network: "devnet",
  }))?.walletId === rpcWalletId,
);
check(
  "adapter refuses a scope whose stored row does not match",
  await rejects(() => rpcStore.findByScope({ ...rpcScope, membershipId: rpcScope.membershipId })) === false,
);
check(
  "adapter propagates a routine failure instead of inventing a row",
  await rejects(() =>
    rpcStore.insertIfAbsent({
      ...rpcCandidate,
      walletId: randomUUID(),
      scope: { ...rpcScope, groupId: randomUUID() },
    }),
  ),
);

// -------------------------------------------------------------------------- ACLs
for (const table of ["devnet_wallets", "devnet_wallet_events"]) {
  for (const role of ["public", "anon", "authenticated", "service_role"]) {
    for (const priv of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
      const r = await db.query<{ ok: boolean }>(
        `SELECT has_table_privilege($1, $2, $3) AS ok`,
        [role, `public.${table}`, priv],
      );
      check(`${role} has no ${priv} on ${table}`, r.rows[0]?.ok === false);
    }
  }
  const rls = await db.query<{ relrowsecurity: boolean; relforcerowsecurity: boolean }>(
    `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`,
    [`public.${table}`],
  );
  check(`${table}: row level security enabled`, rls.rows[0]?.relrowsecurity === true);
  check(`${table}: row level security forced`, rls.rows[0]?.relforcerowsecurity === true);
  const policies = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_policies WHERE tablename = $1
       AND coalesce(qual, 'false') = 'false' AND coalesce(with_check, 'false') = 'false'`,
    [table],
  );
  check(`${table}: all four policies deny`, policies.rows[0]?.n === 4);
}

const routines: [string, string][] = [
  ["provision_devnet_wallet", "public.provision_devnet_wallet(uuid,uuid,uuid,text,text,text,text,jsonb)"],
  ["read_devnet_wallet_scoped", "public.read_devnet_wallet_scoped(uuid,uuid,text,text)"],
  ["read_devnet_wallet_by_telegram", "public.read_devnet_wallet_by_telegram(text,text)"],
  ["read_devnet_wallet_envelope", "public.read_devnet_wallet_envelope(uuid,uuid,uuid,text,text)"],
];
for (const [name, signature] of routines) {
  for (const role of ["public", "anon", "authenticated"]) {
    const r = await db.query<{ ok: boolean }>(`SELECT has_function_privilege($1, $2, 'EXECUTE') AS ok`, [role, signature]);
    check(`${role} cannot execute ${name}`, r.rows[0]?.ok === false);
  }
  const server = await db.query<{ ok: boolean }>(`SELECT has_function_privilege('service_role', $1, 'EXECUTE') AS ok`, [signature]);
  check(`server role can execute ${name}`, server.rows[0]?.ok === true);
  const def = await db.query<{ prosecdef: boolean; proconfig: string[] | null }>(
    `SELECT prosecdef, proconfig FROM pg_proc WHERE oid = $1::regprocedure`,
    [signature],
  );
  check(`${name} is SECURITY DEFINER`, def.rows[0]?.prosecdef === true);
  check(`${name} pins search_path=pg_catalog`, (def.rows[0]?.proconfig ?? []).includes("search_path=pg_catalog"));
}
for (const [label, signature] of [
  ["immutability trigger", "public.devnet_wallets_immutable()"],
  ["append-only audit trigger", "public.devnet_wallet_events_append_only()"],
  ["envelope validator", "public.devnet_wallets_envelope_ok(jsonb,uuid,uuid,uuid,text,text)"],
  ["base64 validator", "public.devnet_envelope_b64_ok(jsonb,integer)"],
] as const) {
  for (const role of ["public", "anon", "authenticated", "service_role"]) {
    const r = await db.query<{ ok: boolean }>(`SELECT has_function_privilege($1, $2, 'EXECUTE') AS ok`, [role, signature]);
    check(`${role} cannot execute the ${label}`, r.rows[0]?.ok === false);
  }
}

await db.close();
console.log(`\n${pass} passed, ${fail} failed`);
console.log(
  "NOTE: envelope fixtures are structurally realistic synthetic values (random padding), never real keys or ciphertexts. Same-session sequencing is not multi-session concurrency.",
);
if (fail > 0) process.exit(1);
