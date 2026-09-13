# BRUH Devnet Signer — runtime validation record

Project: BRUH Devnet Signer (isolated backend and secret scope; separate from
Crypto Companion Bot and BlackBox.Farm).
Network: **devnet only**. No funding, no broadcast, no mainnet, no imported
keys, no production wrapping key.

## Commit

Validated at commit `af439912be9e7e8f999236342085608058a997bc`
(run date: 2026-09-13 UTC). GitHub sync: `systemreset-ca/bruh-devnet-guardian`
(separate repository from `bruhlegends`; local clone HEAD
`88e0590fdae9316effaae50f83753d6243ab7fa1`).

## Pinned dependency versions

| Package | Version | Pinned exactly |
| --- | --- | --- |
| `@solana/web3.js` | 1.98.4 | yes |
| `@noble/curves` | 2.3.0 | yes |
| `bs58` | 6.0.0 | yes |

Runtime: Node 22 (v22.22.0) for local test runs; Cloudflare-style worker
runtime for the production build/SSR target. All cryptography uses platform Web
Crypto (`node:crypto` `webcrypto`) plus pure-JS `@noble/curves`. No native
addons.

## Reference pattern source (read-only, never modified)

`systemreset-ca/bruhlegends`, draft PR 46, branch `codex/devnet-custody-core`:

- `src/lib/custody-vault.server.ts` — AES-256-GCM envelope, caller-supplied
  non-extractable wrapping key, AAD scope binding, no raw seed export
- `services/custody-signer/sol-transfer.ts` — constrained single-instruction SOL
  transfer construction/signing (RPC, fee probing and broadcast deliberately
  excluded from this project's copy)

## Validation scope — what has and has not been exercised

These three are distinct and must not be conflated:

1. **Local Node test runs — VERIFIED.** `scripts/sdk-smoke.ts` and
   `scripts/custody-selftest.ts` execute under Node 22 (`bun`) on this machine.
   All cryptography, envelope, transfer-construction and request-auth logic is
   verified here only.
2. **Worker bundle build — VERIFIED.** `bun run build` produces the
   Cloudflare-style worker bundle successfully. This proves the modules bundle
   and resolve for the worker target; it does **not** execute them.
3. **Deployed Worker execution — NOT VERIFIED.** No code in this project has
   been observed executing inside the actual Worker runtime. Attempts to
   exercise the built bundle locally (`vite preview`, `wrangler dev`) did not
   produce a usable result, and nothing is deployed. Therefore worker-runtime
   behaviour of Web Crypto, the `rpc-websockets` stub path, and the fail-closed
   auth path is **unproven**.

Correction to an earlier report: an interrupted run had created a diagnostic
HTTP route at `src/routes/api/public/signer/selftest.ts`, contrary to a report
that claimed no endpoint existed. That route has been **removed**. Self-checks
are CLI-only (`scripts/`); the project exposes no signer or diagnostic HTTP
endpoint of any kind. Because no caller secret or key ID was ever configured,
the route denied all access while it existed and no funded or signing operation
occurred.

## Production build

`bun run build` — **PASS**, built in 278 ms, nitro output generated
(`dist/nitro.json`), `@solana/web3.js` bundled for the worker target
(656.48 kB / 145.25 kB gzip).

Fix required to reach a passing worker build: `@solana/web3.js` 1.x statically
imports `rpc-websockets`, whose package `exports` resolve only under
node/browser conditions, so it cannot be bundled for the worker runtime. A
build-time alias in `vite.config.ts` replaces it with
`src/lib/custody/rpc-websockets-unsupported.ts`, which throws if a subscription
is ever opened. This signer never opens one (offline build + sign, no
broadcast).

## SDK compatibility smoke — `bun run scripts/sdk-smoke.ts`

Module: `src/lib/custody/sdk-smoke.server.ts` (server-only; not reachable from
any route, public or authenticated).

**9 passed, 0 failed:**

| Check | Result |
| --- | --- |
| ephemeralKeypairGenerated (SDK keypair matches `@noble/curves` pubkey) | PASS |
| aesGcmKeyGenerated (32-byte key, AES-GCM 256, non-extractable) | PASS |
| seedRoundTripsWithScopedAad (12-byte IV, +16-byte tag, exact seed recovered) | PASS |
| wrongAadRejected (mismatched authenticated data fails to decrypt) | PASS |
| transferHasSingleSystemInstruction | PASS |
| referenceIsReadonlyAndUnique (non-signer, non-writable, unique account keys) | PASS |
| recipientMatches (decoded System transfer destination) | PASS |
| lamportsMatch (decoded lamports equal approved amount) | PASS |
| ed25519SignatureVerified (signature verified over serialized message) | PASS |

## Custody / auth self-check — `bun run scripts/custody-selftest.ts`

**40 passed, 0 failed** (envelope structure, authentication, AAD scope binding,
foreign-key and extractable-key rejection, rotation, offline signature
verification, sender / zero-lamport / fee-cap / mainnet / recipient-mismatch /
tampered-record rejections, and the fail-closed request-auth suite: replay,
missing or short secret, missing configured expected key ID, caller key-ID
substitution, key-ID binding into the HMAC canonical input, missing durable
nonce store, nonce-store outage, concurrent same-nonce attempts (exactly one
accepted), body-digest binding, clock skew, wrong secret, path and method
binding, missing headers, oversized body).

## Request authentication model

`src/lib/custody/request-auth.server.ts` is async and fail-closed:

- The HMAC-SHA256 canonical input binds scheme version, expected key ID,
  method, path, timestamp, nonce and the SHA-256 digest of the exact raw body.
- The expected key ID must be configured explicitly. A caller-supplied key ID
  that differs is rejected (constant-time compare), and the expected value —
  not the caller's — is what gets signed over.
- Replay protection requires an explicit **atomic durable** nonce-consumption
  callback. The production module contains **no in-memory nonce store**: a
  process-local Map cannot stop replay across Worker instances or restarts.
  A missing store, a non-atomic `false` result, or any store error rejects the
  request. Nonce store errors are never logged (they can carry request-derived
  material).
- `src/lib/custody/nonce-store.server.ts` resolves the durable consumer from
  this project's own Cloud backend (see below). It returns `null` when the
  backend is not configured, which denies the request — there is still no
  in-memory or test fallback in production code.
- The only in-memory nonce store lives in the test harness
  (`scripts/support/in-memory-nonce-store.ts`) and is never importable from
  production modules.

## Durable nonce storage (this project's backend only)

Objects (applied migration):

- `public.signer_nonces` — primary key `(key_id, nonce)`, `consumed_at`,
  `expires_at`; index on `expires_at`.
- `public.consume_signer_nonce(key_id text, nonce text, ttl_seconds integer)
  RETURNS boolean` — `SECURITY DEFINER`, `SET search_path = public`.

Grants (exact):

```sql
REVOKE ALL ON TABLE public.signer_nonces FROM anon;
REVOKE ALL ON TABLE public.signer_nonces FROM authenticated;
REVOKE ALL ON TABLE public.signer_nonces FROM service_role;
REVOKE ALL ON FUNCTION public.consume_signer_nonce(text,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.consume_signer_nonce(text,text,integer) FROM anon;
REVOKE ALL ON FUNCTION public.consume_signer_nonce(text,text,integer) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.consume_signer_nonce(text,text,integer) TO service_role;
```

No Data API role holds any table privilege, so direct client or server-role
reads/writes are impossible. RLS is `ENABLE`d and `FORCE`d with four explicit
deny-all policies. The routine is the single access path.

Routine constraints: `key_id` must match `^[A-Za-z0-9_.:-]{8,64}$`, `nonce`
must match `^[A-Za-z0-9_-]{16,128}$`, and `ttl_seconds` must be 1–300 —
anything else raises. Expiry is computed from the server clock (`now()`) only;
no caller-supplied timestamp is accepted. Each call deletes at most 200 expired
rows. First use is a single atomic
`INSERT ... ON CONFLICT (key_id, nonce) DO UPDATE ... WHERE expires_at < now()
RETURNING true`, so a replay within the window returns `false` and an expired
row is reclaimable exactly once.

Adapter: `getDurableNonceConsumer()` derives `ttl_seconds` from the verifier's
own window (never a caller value), fails closed if that value falls outside
1–300 rather than clamping it, and throws on any store error without logging
the error body (it can echo request-derived values).

### SQL test results — 23 passed, 0 failed (single database session)

`scripts/sql/nonce-store-tests.sql`. Covers: first use true, replay false,
server-clock expiry bounds, expired-row reclaimed exactly once, rejection of
short/invalid `key_id`, short/invalid/NULL `nonce`, zero/negative/NULL and
over-300s TTL, bounded cleanup of 50 expired rows, and ACL assertions (no table
privileges for `anon`, `authenticated` or `service_role`; RLS enabled and
forced; all four policies deny; only `service_role` may execute the routine;
routine is `SECURITY DEFINER`).

**Labelling:** the `sequential_same_nonce_one_winner` check runs two attempts in
**one** session. That is sequential execution, **not** concurrency, and it does
not by itself prove atomicity across sessions.

### Real multi-session concurrency — 12 passed, 0 failed

`scripts/nonce-concurrency-test.ts`. Each attempt is a separate HTTP request to
the routine, so attempts land on **distinct database sessions/connections**.
8 trials × 6 simultaneous requests for the same `(key_id, nonce)` produced
**exactly one** first-use winner in every trial; 6 simultaneous distinct nonces
all succeeded; TTL values 0, -1 and 3600 were rejected server-side.

Note: the sandbox database role cannot execute the routine or create schemas, so
these tests were driven through the Data API with the server role. Test output
is booleans and counts only.

## Secret handling

- Ephemeral seeds and AES keys are generated in memory for a single check and
  best-effort zeroed in a `finally` block. They are never written to disk,
  persisted, returned, or logged.
- Test output is booleans and non-secret metadata only.
- No demo or default secret exists anywhere; missing caller secret rejects.
- No secret material is exposed to the browser; authorization headers and
  request bodies are never logged.

## Limitations (current state)

- No RPC adapter, fee probing, broadcast or confirmation inspection in this
  project — signing and verification are entirely offline.
- No wallet funding, mainnet endpoints, imported keys, or generated production
  wrapping key.
- Websocket RPC subscriptions are unavailable in the worker runtime by design
  (aliased stub throws).
- JavaScript cannot guarantee memory erasure; zeroing is defence-in-depth only.
- Worker runtime excludes native addons, `child_process`, `sharp`-class
  packages, and file watching; only pure-JS / Web Crypto paths are usable.
- The self-check and SDK smoke modules are CLI-only; there is **no** HTTP route
  in this project (`src/routes` contains only the root layout and the operator
  status page).
- Request authentication has never been exercised over real HTTP — only via
  direct in-process calls in the CLI test suite.
- Durable nonce storage now exists in this project's own backend and is tested
  (single-session SQL suite plus real multi-session concurrency). It has **not**
  been exercised from inside the deployed Worker runtime — see the validation
  scope section; nothing is deployed.
- Caller secrets (`SIGNER_CALLER_SECRET`, `SIGNER_CALLER_KEY_ID`) are not
  configured, so authentication denies every request regardless of the store.
- Expired-row cleanup is opportunistic (max 200 rows per consumption call);
  there is no scheduled vacuum job.
- No signing HTTP route, keys, secrets, funded activation or schema exist.

## Revision history / GitHub

This project can be connected to its **own separate repository** via
**Settings → GitHub → Connect to GitHub** in the project editor. Each Lovable
project maps to a distinct repository, so connecting BRUH Devnet Signer does not
affect or disconnect the BRUH (`bruhlegends`) repository connection.

## Nonce RPC alignment (proposed, NOT applied) — 2026-09-13

### Process correction
The previous durable-nonce migration was applied immediately. That was out of
order: the source/test report should precede any Cloud application. No further
schema change has been applied in this slice. The alignment SQL below is a
proposal only, held for the owner's source/test review.

### Applied state (unchanged in this slice)
- `public.signer_nonces` exists, RLS enabled and forced, four deny-all policies.
- `public.consume_signer_nonce(text,text,integer)` exists as SECURITY DEFINER
  with `search_path = public`, accepting `ttl_seconds` in the range 1–300, key
  regex `^[A-Za-z0-9_.:-]{8,64}$`, nonce regex `^[A-Za-z0-9_-]{16,128}$`.
- EXECUTE granted to `service_role` only; table privileges revoked from
  `anon`, `authenticated`, `service_role` (PUBLIC not yet revoked explicitly).
- No caller secret or key ID is configured, so no request can authenticate.

### Proposed change (`docs/proposed-migration-nonce-v2.sql`)
- Fixed retention: any `ttl_seconds` other than `300` raises. A 1-second TTL
  would let a nonce be reclaimed while the verifier's 60-second timestamp
  window is still valid, permitting replay.
- `key_id` regex aligned to the verifier: `^[A-Za-z0-9._-]{1,64}$`.
- `nonce` regex aligned to canonical lowercase hex: `^[0-9a-f]{32,64}$`.
- `SET search_path = pg_catalog`, every table reference schema-qualified and
  built-ins called as `pg_catalog.*`, so `pg_temp` cannot shadow anything.
- `REVOKE ALL ... FROM PUBLIC` on both the table and the routine, in addition
  to the API roles.

Exact SQL and grants: `docs/proposed-migration-nonce-v2.sql` (verbatim, will be
applied byte-for-byte if approved).

### Source changes applied in this slice (no schema, no endpoints, no secrets)
- `request-auth.server.ts`: nonce header must be canonical lowercase hex
  (`^[0-9a-f]{32,64}$`, case-sensitive); no normalisation of caller input.
- `nonce-store.server.ts`: retention is the fixed 300 seconds; the adapter
  fails closed if the verifier window is not exactly 300s (never clamps).

### Test results
- CLI custody/auth suite: 45/45 PASS, including new checks — request accepted
  at 58s age (2s of window left), replay with 2s of window remaining rejected,
  retention (300s) exceeds the timestamp window (60s), verifier requests
  exactly 300s retention, non-canonical uppercase hex nonce rejected.
- SDK smoke: 9/9 PASS. Typecheck: clean. Production Worker bundle build: PASS.
- SQL suite `scripts/sql/nonce-store-tests.sql` now carries 30 assertions,
  including replay-with-2s-remaining, TTL 60/299/301 rejected, PUBLIC role has
  no table privileges and cannot execute, and routine `search_path=pg_catalog`.
  These SQL assertions have NOT been run: they assert the proposed routine, and
  no schema change was applied. They will be run immediately after approval.

### Still unverified
Execution inside a deployed Worker runtime (nothing deployed).
