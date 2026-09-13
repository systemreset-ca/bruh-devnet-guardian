/**
 * ACTUAL isolated PostgreSQL checks for the PROPOSED wallet envelope schema.
 *
 * Runs docs/proposed-migration-wallets.sql verbatim inside an in-process PGlite
 * database. Nothing here touches the project's Cloud backend: the proposal is
 * NOT applied there. Output is names, booleans and counts only — no envelope
 * bytes, seeds or keys (envelopes here are inert placeholder JSON).
 *
 * Concurrency note: PGlite exposes a single session, so same-scope repeat
 * attempts below are SEQUENTIAL, not real multi-session concurrency. Real
 * parallel behaviour must be re-measured after the migration is applied.
 */
import { readFileSync } from "node:fs";
import { PGlite } from "@electric-sql/pglite";

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

const scope = {
  group: "11111111-1111-4111-8111-111111111111",
  membership: "22222222-2222-4222-8222-222222222222",
  chat: "-1001234567890",
  user: "4242424242",
};
const ADDRESS_A = "9nKPTBzKfvJc8wKq3iYtHwv7BqPMc2Uv1YtQhqR3FvWx";
const ADDRESS_B = "7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKvnpTMr1";
const envelope = JSON.stringify({ placeholder: true });

async function provision(walletId: string, address: string, overrides: Partial<typeof scope> = {}) {
  const s = { ...scope, ...overrides };
  const result = await db.query<{ wallet_id: string; address: string; created: boolean }>(
    `SELECT * FROM public.provision_devnet_wallet($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
    [walletId, s.group, s.membership, s.chat, s.user, "wrap-v1", address, envelope],
  );
  return result.rows[0]!;
}

async function rejects(sql: string, params: unknown[] = []): Promise<boolean> {
  try {
    await db.query(sql, params);
    return false;
  } catch {
    return true;
  }
}

const WALLET_A = "33333333-3333-4333-8333-333333333333";
const WALLET_B = "44444444-4444-4444-8444-444444444444";

const first = await provision(WALLET_A, ADDRESS_A);
check("first provisioning inserts and reports created=true", first.created === true);
check("returned wallet id is the server-supplied UUID", first.wallet_id === WALLET_A);

const second = await provision(WALLET_B, ADDRESS_B);
check("sequential repeat for the same scope reports created=false", second.created === false);
check("repeat returns the already persisted wallet id", second.wallet_id === WALLET_A);
check("repeat never overwrites the address", second.address === ADDRESS_A);

const count = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM public.devnet_wallets`);
check("exactly one row per scope", count.rows[0]?.n === 1);

const other = await provision(
  "55555555-5555-4555-8555-555555555555",
  ADDRESS_B,
  { membership: "66666666-6666-4666-8666-666666666666" },
);
check("a different membership scope gets its own wallet", other.created === true);

const stored = await db.query<{
  network: string;
  frozen: boolean;
  telegram_chat_id: string;
  telegram_user_id: string;
}>(`SELECT network, frozen, telegram_chat_id, telegram_user_id FROM public.devnet_wallets WHERE wallet_id = $1`, [WALLET_A]);
check("network is stored as devnet", stored.rows[0]?.network === "devnet");
check("account is stored frozen", stored.rows[0]?.frozen === true);
check(
  "scope binds telegram chat id and user id",
  stored.rows[0]?.telegram_chat_id === scope.chat && stored.rows[0]?.telegram_user_id === scope.user,
);

check(
  "duplicate address for a new scope rejected",
  await rejects(
    `SELECT * FROM public.provision_devnet_wallet($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
    ["77777777-7777-4777-8777-777777777777", scope.group, "88888888-8888-4888-8888-888888888888", scope.chat, scope.user, "wrap-v1", ADDRESS_A, envelope],
  ),
);

// -------------------------------------------------------------- input constraints
const bad: [string, unknown[]][] = [
  ["invalid chat id rejected", ["99999999-9999-4999-8999-999999999999", scope.group, scope.membership, "abc", scope.user, "wrap-v1", ADDRESS_B, envelope]],
  ["invalid user id rejected", ["99999999-9999-4999-8999-999999999999", scope.group, scope.membership, scope.chat, "-5", "wrap-v1", ADDRESS_B, envelope]],
  ["invalid key version rejected", ["99999999-9999-4999-8999-999999999999", scope.group, scope.membership, scope.chat, scope.user, "bad version!", ADDRESS_B, envelope]],
  ["invalid address rejected", ["99999999-9999-4999-8999-999999999999", scope.group, scope.membership, scope.chat, scope.user, "wrap-v1", "0OIl-not-base58", envelope]],
  ["null wallet id rejected", [null, scope.group, scope.membership, scope.chat, scope.user, "wrap-v1", ADDRESS_B, envelope]],
  ["non-object envelope rejected", ["99999999-9999-4999-8999-999999999999", scope.group, scope.membership, scope.chat, scope.user, "wrap-v1", ADDRESS_B, JSON.stringify("nope")]],
];
for (const [name, params] of bad) {
  check(
    name,
    await rejects(`SELECT * FROM public.provision_devnet_wallet($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, params),
  );
}
check(
  "non-devnet network rejected by the check constraint",
  await rejects(
    `INSERT INTO public.devnet_wallets (wallet_id, group_id, membership_id, telegram_chat_id, telegram_user_id, network, wrapping_key_version, address, envelope) VALUES ($1,$2,$3,$4,$5,'mainnet-beta','wrap-v1',$6,$7::jsonb)`,
    ["99999999-9999-4999-8999-999999999999", scope.group, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", scope.chat, scope.user, ADDRESS_B, envelope],
  ),
);
check(
  "unfrozen account rejected by the check constraint",
  await rejects(
    `INSERT INTO public.devnet_wallets (wallet_id, group_id, membership_id, telegram_chat_id, telegram_user_id, wrapping_key_version, address, envelope, frozen) VALUES ($1,$2,$3,$4,$5,'wrap-v1',$6,$7::jsonb,false)`,
    ["99999999-9999-4999-8999-999999999999", scope.group, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", scope.chat, scope.user, ADDRESS_B, envelope],
  ),
);

// ------------------------------------------------------------------ immutability
for (const [name, column, value] of [
  ["wallet id immutable", "wallet_id", "'99999999-9999-4999-8999-999999999999'"],
  ["group id immutable", "group_id", "'99999999-9999-4999-8999-999999999999'"],
  ["membership id immutable", "membership_id", "'99999999-9999-4999-8999-999999999999'"],
  ["telegram chat id immutable", "telegram_chat_id", "'-100999'"],
  ["telegram user id immutable", "telegram_user_id", "'1'"],
  ["network immutable", "network", "'devnet'::text || ''"],
  ["key version immutable", "wrapping_key_version", "'wrap-v2'"],
  ["address immutable", "address", `'${ADDRESS_B}'`],
] as const) {
  const isNoop = column === "network";
  const failed = await rejects(
    `UPDATE public.devnet_wallets SET ${column} = ${value} WHERE wallet_id = $1`,
    [WALLET_A],
  );
  check(name, isNoop ? !failed : failed);
}

// ------------------------------------------------------------------ read routines
const publicRead = await db.query<Record<string, unknown>>(
  `SELECT * FROM public.read_devnet_wallet_public($1,$2,$3,$4)`,
  [scope.group, scope.membership, scope.chat, scope.user],
);
check(
  "public read returns metadata only, no envelope column",
  Object.keys(publicRead.rows[0] ?? {}).sort().join(",") === "address,frozen,wallet_id,wrapping_key_version",
);
check("public read returns the persisted address", publicRead.rows[0]?.["address"] === ADDRESS_A);
const envRead = await db.query<{ read_devnet_wallet_envelope: unknown }>(
  `SELECT public.read_devnet_wallet_envelope($1)`,
  [WALLET_A],
);
check("signer-only envelope read returns an object", typeof envRead.rows[0]?.read_devnet_wallet_envelope === "object");

// -------------------------------------------------------------------------- ACLs
for (const role of ["public", "anon", "authenticated", "service_role"]) {
  for (const priv of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
    const r = await db.query<{ ok: boolean }>(
      `SELECT has_table_privilege($1, 'public.devnet_wallets', $2) AS ok`,
      [role, priv],
    );
    check(`${role} has no ${priv} on devnet_wallets`, r.rows[0]?.ok === false);
  }
}
const rls = await db.query<{ relrowsecurity: boolean; relforcerowsecurity: boolean }>(
  `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'public.devnet_wallets'::regclass`,
);
check("row level security enabled", rls.rows[0]?.relrowsecurity === true);
check("row level security forced", rls.rows[0]?.relforcerowsecurity === true);
const policies = await db.query<{ n: number }>(
  `SELECT count(*)::int AS n FROM pg_policies WHERE tablename = 'devnet_wallets'
     AND coalesce(qual, 'false') = 'false' AND coalesce(with_check, 'false') = 'false'`,
);
check("all four policies deny", policies.rows[0]?.n === 4);

const routines: [string, string][] = [
  ["provision_devnet_wallet", "public.provision_devnet_wallet(uuid,uuid,uuid,text,text,text,text,jsonb)"],
  ["read_devnet_wallet_public", "public.read_devnet_wallet_public(uuid,uuid,text,text)"],
  ["read_devnet_wallet_envelope", "public.read_devnet_wallet_envelope(uuid)"],
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
  check(
    `${name} pins search_path=pg_catalog`,
    (def.rows[0]?.proconfig ?? []).includes("search_path=pg_catalog"),
  );
}
const trigger = await db.query<{ ok: boolean }>(
  `SELECT has_function_privilege('service_role', 'public.devnet_wallets_immutable()', 'EXECUTE') AS ok`,
);
check("no API role may execute the immutability trigger function", trigger.rows[0]?.ok === false);

await db.close();
console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
