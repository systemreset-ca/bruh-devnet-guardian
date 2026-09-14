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

## V2 nonce migration — applied (2026-09-13)

Independent Codex review validated the corrected V2 SQL against isolated PGlite
(15 assertions). Under owner standing authorization, that exact SQL was then
applied to this project's own Cloud backend as a **new** migration journal entry;
the original nonce migration file is preserved unchanged.

Applied changes (nonce-only; no other schema touched):

- `public.consume_signer_nonce(text, text, integer)` replaced:
  - `SECURITY DEFINER SET search_path = pg_catalog`, every table reference
    schema-qualified (`pg_temp` cannot shadow).
  - Fixed retention: any `ttl_seconds` other than `300` raises. A shorter TTL
    would let a nonce be reclaimed while the verifier's 60-second timestamp
    window still accepts the same request.
  - `key_id` regex `^[A-Za-z0-9._-]{1,64}$` (matches the verifier).
  - `nonce` regex `^[0-9a-f]{32,64}$` (canonical lowercase hex; the verifier
    *rejects* uppercase rather than normalizing it).
  - Expiry from `pg_catalog.now()` only; bounded cleanup of ≤200 expired rows
    per call; atomic `INSERT ... ON CONFLICT ... WHERE expires_at < now()`.
  - `RETURN COALESCE(v_first_use, false)` (not `pg_catalog.coalesce`).
- Grants: `REVOKE ALL` on `public.signer_nonces` from `PUBLIC`, `anon`,
  `authenticated`, `service_role`; `REVOKE ALL` on the routine from `PUBLIC`,
  `anon`, `authenticated`; `GRANT EXECUTE` on the routine to `service_role` only.
- Table RLS remains enabled and forced with four deny-all policies.

Adapter alignment: `getDurableNonceConsumer()` now requires the verifier's own
window to be exactly 300 s and always sends `300`; any other derived value throws
(fail closed, no clamping). Still no missing-store fallback.

### Test evidence (actual runs, this slice)

| Suite | Result | Scope |
| --- | --- | --- |
| SQL suite (`scripts/sql/nonce-store-tests.sql`) | **35/35 PASS** | single database session |
| Real parallel HTTP trials (`scripts/nonce-concurrency-test.ts`) | **18/18 PASS** | separate sessions per request |
| Custody/auth CLI self-check | **41/41 PASS** | local Node, in-process |
| SDK compatibility smoke | **9/9 PASS** | local Node, in-process |
| Typecheck | clean | — |
| Worker bundle build (`bun run build`) | **PASS** | bundle only, not executed |

SQL suite covers: first use, replay, fixed-300s server-clock expiry, replay with
2 s remaining rejected, expired row reclaimed exactly once, 1-char key accepted,
key over 64 chars / bad charset / NULL rejected, nonce <32 / >64 / uppercase /
non-hex / NULL rejected, TTL 1 / 60 / 299 / 301 / 0 / -1 / NULL rejected,
bounded cleanup of 50 expired rows, sequential same-nonce one winner (labelled
single-session, not concurrency), PUBLIC + anon + authenticated + service_role
table privileges absent, RLS enabled and forced, four deny-all policies, routine
EXECUTE denied to PUBLIC/anon/authenticated and granted to service_role only,
routine is SECURITY DEFINER with `search_path=pg_catalog`.

Parallel HTTP trials: 8 trials x 6 simultaneous same-nonce requests, exactly one
winner each; 6 simultaneous distinct nonces all first use; live-nonce replay
rejected; uppercase nonce rejected; TTL 0, -1, 1, 60, 299, 301, 3600 rejected.

### Managed editor "Build unsuccessful" / "Preview is out of date"

Investigated on latest main:

- `bun run build` (Worker bundle): **PASS**, nitro output generated.
- Typecheck: clean.
- Managed preview: serving **HTTP 200** at `/` after refresh.
- Cause in the dev-server log: stale entries from the earlier slice — reloads of
  the since-deleted `src/routes/api/public/signer/selftest.ts` and a transient
  Vite dependency-optimizer miss for `@supabase/supabase-js`
  (`.vite/deps` file not found, re-optimized on the next start). Both are stale
  editor state, not a source defect; `src/routes` now contains only the root
  layout and the operator status page.

Still **not** verified: execution inside a deployed Worker runtime (nothing is
deployed). No wallet/signing endpoints, caller secrets, wrapping keys, funds or
mainnet exist.

## V2 adapter/timing restoration (audit follow-up)

The audit at GitHub `d522c00` was correct: at that commit the adapter still used
`MIN_TTL_SECONDS=1`/`MAX_TTL_SECONDS=300` with a variable derived TTL, and the
self-check suite had 41 checks without the near-expiry and fixed-retention
assertions. An earlier report claiming 45 checks was inaccurate; that claim is
withdrawn. Both requirements have now been (re)implemented on top of the applied
Cloud update, and nothing was removed:

- `src/lib/custody/nonce-store.server.ts`: requires `expiresAt - now === 300000`
  exactly and always sends `p_ttl_seconds: 300`. Any other derived value throws
  (fail closed) — no range, no clamping, no fallback.
- `scripts/custody-selftest.ts`: added
  - request with a 58 s old timestamp accepted (near the 60 s skew edge);
  - the same nonce still rejected (`replayed_nonce`) while that timestamp is
    still valid;
  - the callback's requested retention is exactly 300000 ms (300 s);
  - requested retention exceeds the 60 s timestamp window.

### Actual results after restoration

| Check | Result |
| --- | --- |
| Custody/auth CLI self-check | **45/45 PASS** (was 41) |
| Typecheck | clean |
| Worker bundle build | **PASS** (bundle only, not executed) |
| Managed preview `/` | **HTTP 200** |

Pre-existing suites are unchanged and still recorded above: SQL suite 35/35 and
real parallel HTTP trials 18/18 were run against the applied V2 routine earlier
in this session; they were not re-run in this restoration step, which touched
only the adapter and the CLI suite. Local source SHA before this commit:
`630061a`. Worker-runtime execution remains unverified; no wallet/signing
endpoints, caller secrets, wrapping keys, funds or mainnet exist.

## Telegram third-party initData verification (source-only slice, 2026-09-13)

Module: `src/lib/telegram/init-data.server.ts` (server-only, no HTTP route).
Reference: https://core.telegram.org/bots/webapps#validating-data-for-third-party-use

- Ed25519 third-party path only; **no bot token** is used or required.
- Pinned in server config, never accepted from a request: bot ID `8763268934`
  (@BRUHLegendsBot) and Telegram production public key
  `e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d`.
- Canonical string: `"<bot_id>:WebAppData\n"` + all received fields except
  `hash` and `signature`, sorted by key, `key=value` joined with `\n`.
  Signature is base64url Ed25519 over that string.
- Rejections: duplicate parameters, missing/malformed signature, malformed
  `auth_date`, malformed/non-numeric user ID, stale payloads (default 300 s),
  future payloads (> 60 s skew), payloads over 4096 bytes, empty/malformed
  query strings, and invalid pinned config.
- `initDataUnsafe` is not trusted (only the raw signed query string is parsed).
  No group/channel membership and no Telegram 2FA state is inferred.
- Nothing is logged: no initData, signatures, user payloads or key material.

### Evidence classification (important)

- CLI suite `scripts/telegram-initdata-selftest.ts`: **27/27 PASS**.
- Every accepted case uses a **generic, locally generated Ed25519 test key**,
  verified against that same generated key. This proves canonical-string
  construction, bot binding and rejection logic only.
- **No real Telegram signature and no real Telegram account has been verified.**
  Valid live initData is not available yet. The production key and bot ID are
  asserted as pinned constants, and a generated-key fixture is confirmed to be
  REJECTED against the production key.

### Other suites re-run in this slice

- Custody/auth self-check: 45/45 PASS.
- SDK compatibility smoke: 9/9 PASS (network=devnet, broadcast=false).
- Typecheck: clean. Worker bundle build: PASS (283 ms).
- Local source SHA before this commit: `57d8689`.

No public endpoint, credentials, caller secrets, wrapping keys, wallet schema,
funding or mainnet were added in this slice.

## Authenticated runtime diagnostic probe — reintroduced (source-only, 2026-09-13)

Purpose: allow validation of the crypto path inside the ACTUAL deployed Worker
runtime before any funded integration. The earlier diagnostic was removed on
purpose while authentication was incomplete; this reintroduction ships with
complete durable-nonce authentication plus an explicit kill switch.

Files:
- `src/lib/custody/diagnostic-probe.server.ts` — all guards.
- `src/routes/api/public/signer/selftest.ts` — POST-only route; reads per-request
  server env and resolves the durable nonce consumer.
- `scripts/diagnostic-probe-selftest.ts` — CLI guard suite.
- `scripts/live-diagnostic-probe.ts` — trusted live probe (prints status and
  booleans/counts only; never the secret, key ID, signature, nonce or headers).

Guards:
- POST only (GET/other → 405). Body streamed with a hard **1024-byte** cap and
  must be exactly `{}`. No caller key, wallet, address or transaction input.
- Denies (uniform opaque 401) when the caller secret, expected key ID or durable
  nonce store is missing or erroring, and on stale, future, tampered,
  wrong-key-ID, wrong-path or replayed requests.
- Returns 404 (indistinguishable from a missing route) unless the kill switch is
  exactly `"true"`.
- Response body: `ok`, `runtime`, `network`, `broadcast:false`, `checkCount`,
  `passedCount`, and a map of booleans. No address, ciphertext, seed, signature
  or wire bytes. No RPC, broadcast or funding.
- Nothing about the request is logged.

Server secret names (values never in source, tools, chat or logs; no demo
defaults):
- `SIGNER_CALLER_SECRET` — generated as a cryptographically random 64-character
  value by the platform secret manager; the value was never revealed to anyone,
  including the agent.
- `SIGNER_CALLER_KEY_ID` — non-secret identifier `devnet-diagnostic-probe`, bound
  into the HMAC canonical string as the expected key ID.
- `SIGNER_DIAGNOSTIC_ENABLED` — kill switch, currently `"true"`. **Set it to
  `"false"` (or delete it) immediately after the live Worker evidence is
  captured**; the route then returns 404 for everyone.

Evidence:
- Diagnostic probe guard suite: **28/28 PASS** (in-process, TEST-ONLY in-memory
  nonce store and throwaway generated credentials).
- Custody/auth self-check: 45/45 PASS. Telegram initData: 27/27 PASS.
  SDK smoke: 9/9 PASS. Typecheck clean. Worker bundle build PASS.
- Source SHA at this slice: `9394b31`.

Still NOT verified: execution inside the deployed Worker runtime. Nothing has
been published by the agent in this slice; publishing is Codex's step after
review, after which `scripts/live-diagnostic-probe.ts` can be run with the
injected secret.

Scope: this slice authorizes diagnostic auth configuration only — no production
wrapping keys, no wallet provisioning routes, no user funds, no mainnet.

## Adapter exact-window fix and secret-name verification (audit follow-up)

Audit at GitHub main `1b4c3981e9dcff126c7a1c5c47720f0ab1f45de4` was correct:
`nonce-store.server.ts` still derived retention with
`Math.ceil((expiresAt - now) / 1000)`, which accepted any window in
299001..300000 ms. That rounding is removed.

Now: `assertFixedRetentionWindow(now, expiresAt)` requires
`expiresAt - now === 300000` exactly (`FIXED_TTL_MS`), throws
`nonce_ttl_out_of_range` otherwise, and the routine is always called with a
fixed `p_ttl_seconds: 300`. No rounding, no clamping, no fallback.

New offline suite `scripts/nonce-adapter-boundary-test.ts` — **14/14 PASS**:
exact 300000 ms accepted; 299001 / 299500 / 299999 / 300001 / 299000 / 60000 /
1000 / 0 / -1 / 3600000 ms rejected; NaN and non-finite endpoints rejected.

Configured secret NAMES verified via the supported secrets tool (names only,
values never displayed and never available to the agent). Present:
`SIGNER_CALLER_SECRET`, `SIGNER_CALLER_KEY_ID`, `SIGNER_DIAGNOSTIC_ENABLED`,
plus the platform-managed `LOVABLE_API_KEY` and `LOVABLE_CRON_SECRET`. The
secure generation step therefore did succeed; the editor Secrets table listing
only the two managed entries was a stale/filtered view, not a storage failure.
No documentation correction for missing secrets is needed.

Evidence in this slice: adapter boundary 14/14, custody/auth 45/45, Telegram
27/27, diagnostic probe guards 28/28, SDK smoke 9/9 (passed=true), typecheck
clean, Worker bundle build PASS. Source SHA before this commit: `cfc8c83`.
Database SQL suite and parallel HTTP replay trials were NOT re-run in this
slice (source-only change; the applied V2 routine already enforces
`p_ttl_seconds = 300` server-side).

Not published. Deployed Worker execution still unverified. No wrapping keys,
wallet routes, funds or mainnet.

## DEPLOYED WORKER EVIDENCE (captured, diagnostic now disabled)

Reviewed GitHub head at publish: `f6c558cb804ff0c91ed6bc47ee4eeefd4c254000`.
Published host: `bruh-devnet-guardian.lovable.app` (published by Codex, not the
agent).

This is the first evidence in this project about execution inside the **deployed
Worker runtime**. It is separate from, and does not reuse, any local CLI
test-run evidence recorded above.

`scripts/live-diagnostic-probe.ts` (trusted environment, injected credentials,
prints status/booleans/counts only — never the secret, key ID, signature, nonce,
headers or body):

- `status=200`, `ok=true`, `network=devnet`, `broadcast=false`, `checks=9/9`
- PASS: aesGcmEnvelopeSealed, aesGcmEnvelopeAuthenticated,
  aadScopeBindingEnforced, tamperedCiphertextRejected, solTransferSignedOffline,
  ed25519SignatureVerifies, singleSystemTransferInstruction,
  senderMismatchRejected, nonDevnetRejected

`scripts/live-diagnostic-denials.ts` — **3/3 PASS**:

- `deployed_unauthenticated_post_denied` (status=401)
- `deployed_signed_request_accepted` (status=200)
- `deployed_identical_replay_denied` (status=401) — the durable nonce store
  rejected a byte-identical replay of one valid signed request on the deployed
  runtime.

No RPC, no broadcast, no funding, no wallet provisioning occurred. No request
credential, header or body was printed or logged at any point.

Immediately after capture, `SIGNER_DIAGNOSTIC_ENABLED` was set to `"false"`
through the platform secret manager (name and the literal value `false` only;
the caller secret and key ID were never read, printed or touched). The
diagnostic route therefore returns 404 for everyone. `SIGNER_CALLER_SECRET` and
`SIGNER_CALLER_KEY_ID` remain stored, unused and unrevealed.

Operator console: a "Verification evidence" panel now reports local test-run
proof and deployed-runtime proof as separate rows, plus the disabled diagnostic
and the fixtures-only status of third-party sign-in verification.

Source SHA before this commit: `db6217de3ba7674fd76fe799a5033816675c6489`.

### Kill-switch propagation caveat (accurate live state)

`SIGNER_DIAGNOSTIC_ENABLED` is stored as `"false"` in the secret manager
(verified by name; value written as the literal `false`). The **already
published** deployment still evaluated the old value after the change: an
independent live unauthenticated POST returned `401`/`no-store` (the auth
denial) rather than the `404` the disabled path returns, because server
environment values are baked into the running deployment and the switch-off takes
effect on the next publish. No caller credential was exposed by that check.

Codex is publishing the disabled configuration now. The agent will not poll
the live address again. After publish, an unauthenticated POST to the
diagnostic address should return `404`; the operator console already reports
the probe as disabled at source/preview.

No RPC, no broadcast, no funding, no wallet provisioning occurred. Source SHA
before this commit: `db6217de3ba7674fd76fe799a5033816675c6489`; operator
console and caveat updated at `23700cba01eb015d1d7849e258f0a40aa9db24d1`.

## Slice: persistent devnet wallet provisioning (SOURCE-ONLY, nothing applied)

Scope of this slice: source, proposal and tests only. **Nothing was applied,
deployed, enabled or funded.** No signing/provisioning HTTP route exists, no
production wrapping key exists, no user funds and no mainnet.

### Live state after the diagnostic slice (independently confirmed by Codex)

Codex republished the disabled configuration and independently verified a live
POST to the diagnostic address returns `404` with `cache-control: no-store`.
The diagnostic probe is disabled in the live deployment. Documentation-only
PR2 is merged and present in the local history (`7e9d050`).

### Source added (not wired to any route)

- `src/lib/wallets/wallet-store.server.ts` — persistence port. Immutable scope
  (`groupId`, `membershipId`, `telegramChatId`, `telegramUserId`,
  `network: "devnet"`), `insertIfAbsent` is first-writer-wins,
  `publicView()` returns public metadata only.
  `getDurableWalletStore()` resolves to `null` — no durable table is applied,
  so provisioning fails closed with `store_unavailable`. No in-memory fallback
  in production code.
- `src/lib/wallets/authorization.server.ts` — server-owned membership approval
  callback. The verified `telegramUserId` comes from verified initData only;
  approvals are re-bound to the verified user, the claimed chat and UUID-shaped
  group/membership ids. `getProductionMembershipAuthorizer()` resolves to
  `null` → `authorization_unavailable`. Group membership is never derived from
  initData or from a client-selected group.
- `src/lib/wallets/wrapping-key.server.ts` — wrapping keys enter only as an
  explicit non-extractable `CryptoKey` injection with a key version.
  `getProductionWrappingVault()` resolves to `null` →
  `wrapping_key_unavailable`. No demo or fallback production key exists.
- `src/lib/wallets/provisioning.server.ts` — enable gate defaults to false;
  requires the durable HMAC verifier **and** pinned production Telegram
  initData verification **and** the server-owned approval callback; generates
  the keypair server-side; persists one wallet per scope; returns public
  metadata only (`walletId`, `address`, `network`, `wrappingKeyVersion`,
  `frozen`). Accounts are always persisted frozen. No deposits, signing,
  broadcast, withdrawal, export or key import path exists.
- `docs/proposed-migration-wallets.sql` — **proposed, unapplied.**

### Test results (all run just now)

| Suite | Result | Nature of proof |
| --- | --- | --- |
| `scripts/wallet-provisioning-selftest.ts` | **65/65 PASS** | Local Node, offline. Crypto/envelope, auth denial, body contract, authorization binding, idempotence |
| `scripts/wallet-sql-pglite-test.ts` | **69/69 PASS** | Actual isolated PostgreSQL (in-process PGlite) running the proposed SQL verbatim |
| `scripts/custody-selftest.ts` | 45/45 PASS | Local Node |
| `scripts/telegram-initdata-selftest.ts` | 27/27 PASS | Local Node, generated-key fixtures only |
| `scripts/nonce-adapter-boundary-test.ts` | 14/14 PASS | Local Node |
| `scripts/sdk-smoke.ts` | 9/9 PASS | Local Node |
| typecheck | clean | — |
| `bun run build` | PASS (nitro cloudflare-module) | Worker **bundle** builds; not deployed-Worker execution |

Provisioning coverage includes: envelope seal/round-trip under its own scope and
rejection under a different scope; missing caller secret, missing durable nonce
store, stale timestamp, body tampering and byte-identical replay all denied
uniformly with nothing persisted; client-supplied wallet id, key version,
envelope, seed material, group id and network all rejected as
`malformed_request`; missing/erroring/denying authorization callback and
approvals bound to a different user or chat rejected; 6 concurrent same-scope
attempts create exactly **one** wallet with no orphaned second usable key;
distinct scopes get distinct wallets and addresses.

### Explicit limitations of this evidence

- **Mock fixtures, not real proof.** Every accepted path uses a MOCK membership
  approval callback and generated-key initData fixtures. These are **not** real
  BRUH group membership proof and **not** real Telegram signatures. The default
  (pinned production) verifier is separately asserted to reject the generated
  fixture.
- **PGlite is a single session.** Same-scope repeat attempts in the SQL suite
  are sequential. Real multi-session concurrency against the applied routine
  must be re-measured after the migration is applied, as was done for nonces.
- **Missing production configuration is documented, not invented.** No
  production wrapping key, no production membership authorization source and no
  durable wallet table are configured; each path fails closed.
- **Deployed-Worker execution of provisioning is unverified** — there is no
  route and nothing is deployed.

Source SHA before this commit: `ea89f4717cdc3815fef16e0b5bb61c016b93589b`.

## Recorded runtime limitation: no RPC `Connection` support in this Worker build

Not a change to provisioning scope; provisioning source/tests are complete and
unchanged by this note.

Finding: `src/lib/custody/rpc-websockets-unsupported.ts` throws from the
`CommonClient` constructor. `@solana/web3.js` 1.98.4 constructs
`RpcWebSocketClient` unconditionally inside the `Connection` constructor
(original SDK `index.cjs.js` line 6104), so **even a fetch-only `Connection`
cannot be constructed** in this Worker build — construction itself throws, not
just subscription use.

Consequences, stated precisely:

- The deployed-Worker crypto evidence (signed diagnostic `200`, checks 9/9)
  validates **offline** envelope sealing/unsealing, scope binding and offline
  transaction signing and Ed25519 verification **only**. It does **not**
  validate RPC `Connection` support, RPC reads, fee probing, broadcast or any
  network path. No claim of tested RPC exists anywhere in this project.
- The stub is deliberate and must not be silently weakened to make
  `Connection` construct. Any future RPC path must be either a reviewed HTTP
  JSON-RPC adapter (no WebSocket dependency) or a Worker-compatible WebSocket
  dependency, and must be proven with **actual deployed-Worker tests** before
  any funded or live-network use.
- Until such an adapter exists and is tested in the deployed Worker, live
  on-chain reads are unavailable in this signer, so no balance, holdings or
  portfolio value may be reported from it. Nothing may be substituted from the
  database.

Cross-reference: Codex recorded the live disabled diagnostic (`404` with
`cache-control: no-store`) and the signed crypto 9/9 evidence in the public
BRUH draft PR 46 at `fe63b95b0b12a0a77efb99861bcb4e1ddd079834`. That repository
is reference-only and was not modified.

## Review fixes on the source-only wallet provisioning slice (origin/main 0ab23ef follow-up)

Source, proposal and tests only. The wallet schema is still NOT applied to the
Cloud backend, no provisioning endpoint exists, no keys, funds or mainnet.

Changes:
- `src/lib/wallets/wallet-record.server.ts`: strict parsing of any stored row —
  exact envelope key set, version 1, devnet, UUIDs, base58 32-byte address,
  canonical base64 with exact decoded lengths (12-byte IVs, 48-byte AES-GCM
  outputs), envelope-to-row bindings and full scope equality. Failures raise a
  valueless `InvalidWalletRecord` (never echoes stored or request data).
- `publicView` reads network/frozen from the validated record instead of
  hardcoding them, and refuses an invalid record.
- `provisioning.server.ts`: POST-only; every row a store returns (found row,
  winning row, telegram mapping row) is re-validated before use; new
  fail-closed reasons `method_not_allowed`, `inconsistent_mapping`,
  `store_record_invalid`.
- `createRpcWalletStore(rpc)`: narrow controlled-RPC adapter over the four
  proposed routines, with strict row validation and a post-insert re-read. The
  default production factory still returns `null` (fail-closed) until the
  schema and configuration are reviewed and applied.
- `docs/proposed-migration-wallets.sql` (PROPOSED, NOT APPLIED): exact envelope
  structure validation, `UNIQUE (telegram_chat_id, telegram_user_id, network)`,
  fail-closed inconsistent UUID remapping, envelope immutability (no
  replacement in this slice), append-only `devnet_wallet_events` audit written
  in the SAME transaction as creation and holding no envelope material, and a
  fully scoped envelope read (no wallet-id-only read).

Test results (this build):
- `scripts/wallet-record-selftest.ts` — 88/88 PASS (strict record and envelope
  validation, store-distrust, one wallet per Telegram identity).
- `scripts/wallet-provisioning-selftest.ts` — 67/67 PASS.
- `scripts/wallet-sql-pglite-test.ts` — 164/164 PASS, actual isolated
  PostgreSQL (PGlite) against the proposed SQL, including the controlled-RPC
  adapter driven through the real routines.
- `scripts/custody-selftest.ts` 45/45, `scripts/telegram-initdata-selftest.ts`
  27/27, `scripts/nonce-adapter-boundary-test.ts` 14/14,
  `scripts/diagnostic-probe-selftest.ts` 28/28, `scripts/sdk-smoke.ts` 9/9.
- `tsgo --noEmit` clean; `bun run build` PASS.

Limitations (unchanged and explicit):
- Envelope fixtures are structurally realistic SYNTHETIC values built from
  random padding: not real keys, not real ciphertexts.
- Membership approvals in tests are mock callbacks, NOT real BRUH group or
  membership proof; Telegram accept-cases use generated-key fixtures, NOT real
  Telegram signatures.
- PGlite is single-session: same-scope repeats above are sequential, not real
  multi-session concurrency. Real parallel behaviour must be re-measured only
  after a reviewed migration is applied.
- No production authorization callback and no production wrapping key are
  configured; both fail closed and are documented rather than invented.
- Deployed-Worker evidence still covers offline crypto only; no RPC, no
  on-chain reads, no broadcast.

## Source-only read-only devnet RPC slice

Reference: Codex-reviewed public BRUH source `services/custody-signer/http-rpc.ts`
at commit `6ca44ab5060a8250b7df77f28091898a89f5874f` (PR 46), reused with import
names/paths adapted to this signer only; the reviewed logic is unchanged. That
repository is NOT modified. Upstream evidence recorded there (161 BRUH tests,
type/lint pass, exact-source CI run 34788104677 success, one Node public-devnet
read-only prepare) belongs to that project and is cited, not re-claimed here.

Added here:
- `src/lib/custody/http-rpc.server.ts` — `DevnetHttpSolRpc`: no `Connection` and
  no WebSocket construction, explicit server-owned HTTPS endpoint (no userinfo,
  no hash, no redirects), devnet genesis pin, finalized blockhash and finalized
  message fee, exact signed-byte re-derivation before any send, 5 second abort,
  128 KiB streamed response cap, opaque provider errors, no automatic HTTP
  retries. `broadcast`/`inspect` exist for source parity and are NOT wired to
  wallets, provisioning, the bot or any diagnostic path.
- `src/lib/custody/rpc-self-check.server.ts` — read-only self-check: exactly
  three reads (getGenesisHash, getLatestBlockhash finalized, getFeeForMessage
  finalized) against the pinned `https://api.devnet.solana.com`; ephemeral seeds
  generated in memory and zeroed; a transport guard hard-fails if any non-read
  method is ever attempted. Returns booleans and counts only. No provider key is
  needed for these three calls.
- `src/lib/custody/rpc-diagnostic.server.ts` and
  `src/routes/api/public/signer/rpc-selftest.ts` — the same durable
  HMAC + one-time-token auth, kill switch, empty-body contract and uniform
  denials as the crypto diagnostic. No caller endpoint, client params, wallet,
  address or transaction input. No funding, airdrop, sendTransaction or
  broadcast. The diagnostic REMAINS DISABLED: `SIGNER_DIAGNOSTIC_ENABLED` is
  still "false" and was not changed, and nothing was published by the agent.

Test results (this build):
- `scripts/http-rpc-selftest.ts` — 74/74 PASS (endpoint policy, genesis pinning,
  finalized commitments, fee-cap boundary incl. exactly-at-cap, malformed
  blockhash/fee/envelope rejection, id mismatch, error member, non-JSON body,
  128 KiB cap, abort on a hanging provider, no retry on 500/429, opaque provider
  errors, exact signed-byte binding and tamper rejection).
- `scripts/rpc-diagnostic-selftest.ts` — 49/49 PASS (kill switch, POST only,
  empty-body contract incl. rejection of client endpoint/commitment params,
  incomplete config, missing/failing nonce store, header omissions, wrong
  secret, key-ID substitution and unbound key ID, cross-path signature, stale
  and future timestamps, replay denial, uniform opaque denials, and response
  hygiene: no blockhash, no address-shaped string, no wire blob, no provider
  host, pinned endpoint, read methods only).
- Existing suites unchanged and green: custody/auth 45/45, Telegram 27/27, nonce
  boundary 14/14, crypto probe guards 28/28, wallet provisioning 67/67, wallet
  record 88/88, wallet SQL (PGlite) 164/164, SDK smoke 9/9.
- `tsgo --noEmit` clean; `bun run build` PASS.

Actual network evidence in THIS project:
- One real read-only prepare from a local Node environment against public devnet
  succeeded: genesis pinned to devnet, finalized blockhash and block height
  obtained, message fee inside the reserved cap, exactly 3 RPC reads, zero
  broadcast, ephemeral seeds zeroed (10/10 checks).
- NO deployed-Worker RPC proof exists. The deployed-runtime evidence recorded
  earlier still covers offline crypto only. Worker RPC support remains unproven
  until the reviewer enables and publishes the read-only diagnostic and a live
  probe is run.
- No mainnet, no funds, no keys, no airdrop, no broadcast at any point.

## Wallet review fix: authenticated decryption before any address is exposed

Finding (review at 372cc2ed857dca57fe3c5b7b2a127700b937ad58): structural record
validation was in place, but `provisionDevnetWallet` never called the existing
`vault.validate(envelope, identity)`, so a structurally valid but corrupted or
substituted 48-byte ciphertext could have projected an unverified deposit
address. Fixed in source only; the wallet schema is still NOT applied and
provisioning is still disabled.

Changes:
- `provisionDevnetWallet` now runs `vault.validate` (unseal, address
  re-derivation, seed zeroing — no signing) before BOTH the existing-record
  return and the race-winning public projection. Failure is a new fail-closed
  reason `envelope_authentication_failed`; nothing is logged.
- `result.created` must be `typeof === "boolean"`; a non-boolean flag is now
  `store_record_invalid` instead of being coerced to a silent `false`.
- When `created === true`, the persisted row must be the exact candidate:
  walletId, wrapping key version, address, frozen, and every envelope field
  compared field by field (same key count) — scope compatibility alone is no
  longer sufficient.

Tests: `scripts/wallet-record-selftest.ts` 94/94 PASS (was 88), adding: tampered
48-byte ciphertext (canonical base64, correct length, one flipped byte) on both
the stored-row and winning-row paths; a substituted address consistent across
row and envelope on both paths; a genuinely sealed but non-candidate row claimed
as `created=true`; the same row accepted as pre-existing after authentication;
non-boolean created flag. `scripts/wallet-provisioning-selftest.ts` 67/67
unchanged and green. All other suites unchanged: custody 45/45, Telegram 27/27,
nonce boundary 14/14, crypto probe 28/28, RPC client 74/74, RPC diagnostic
49/49, wallet SQL (PGlite) 164/164, SDK smoke 9/9; `tsgo --noEmit` clean;
`bun run build` PASS.

Fixture labelling: every service-accepted row in the provisioning and record
suites carries an ACTUAL throwaway sealed envelope from an ephemeral in-memory
vault, so authenticated decryption is genuinely exercised. Purely structural
synthetic envelopes (random padding) remain in the SQL/PGlite suite and in
rejection cases only, and are explicitly NOT crypto proof. Membership approvals
are mocks, not real BRUH proof. No real keys, funds, endpoints or mainnet.

## Live RPC diagnostic preparation (source + configuration only)

Codex reviewed the RPC diagnostic source at
`61ce1c1e78118ab226c9fbee9f424ae5c07465b0`: pinned public devnet endpoint, three
reads with a hard write-method deny, the existing durable one-time-token auth and
body size cap, no funding, airdrop or broadcast.

Changes in this slice:

- Report field `ephemeralKeysZeroed` renamed to `ephemeralInputSeedsCleared`
  (`src/lib/custody/rpc-self-check.server.ts`, `scripts/http-rpc-selftest.ts`).
  It means exactly this: the seed buffers this module allocated as key input were
  overwritten with zeros. It is NOT a claim that all key material is erased from
  memory. JavaScript and the wallet SDK give no such guarantee — derived key
  objects, internal SDK copies, string values and garbage-collected or relocated
  buffers are outside this module's control. Clearing input seeds is
  defence-in-depth, not proof of erasure.
- New `scripts/live-rpc-diagnostic-probe.ts`: trusted live probe for
  `/api/public/signer/rpc-selftest` using the already-injected diagnostic caller
  credentials (`SIGNER_CALLER_SECRET`, `SIGNER_CALLER_KEY_ID`, names only). It
  sends exactly three requests — unauthenticated (must be denied), one signed
  request, and a byte-identical replay (must be denied by the durable one-time
  token store). It prints only HTTP status, booleans and counts: never the
  secret, key ID, signature, nonce, timestamp, any header, the body or provider
  text. No polling loop.
- `SIGNER_DIAGNOSTIC_ENABLED` set to `"true"` in the secret store for this
  bounded read-only test only (name and literal value only; caller credentials
  never read or touched). Secret changes only take effect live after a
  republish; Codex publishes. The flag is to be set back to `"false"`
  immediately after the live evidence is captured.

Tests: RPC client 74/74, RPC diagnostic guards 49/49, custody 45/45, Telegram
27/27, nonce boundary 14/14, crypto probe 28/28, wallet provisioning 67/67,
wallet record 94/94, SDK smoke 9/9; `tsgo --noEmit` clean; `bun run build` PASS.

Limitation: there is still NO deployed-Worker RPC proof. All RPC responses in the
suites come from local mock transports, and the single real read-only devnet
prepare ran in a local Node environment. Deployed-runtime RPC evidence can only
be claimed after the published run of the live probe. No wallet keys, no funds,
no mainnet.

## Live RPC diagnostic run on the deployed Worker (evidence: PARTIAL FAILURE)

Reviewed and published source `6b05c0a773abc492cd44546a68eb56149a65e179`, with
`SIGNER_DIAGNOSTIC_ENABLED="true"` for this bounded read-only test only. Probe:
`scripts/live-rpc-diagnostic-probe.ts` against
`https://bruh-devnet-guardian.lovable.app/api/public/signer/rpc-selftest`, using
the injected diagnostic caller credentials (names only). No header, body,
signature, nonce, secret or provider text was printed or logged. Exactly three
requests were sent; no polling.

Exact recorded output:

- `unauthenticated_status=401` — unauthenticated live POST denied. PASS
- `signed_status=200` — the signed request was served by the deployed Worker. PASS
- `ok=false network=devnet readOnly=true broadcast=false rpcCalls=1 checks=3/10`
- PASS `endpointPinnedHttps`
- FAIL `onlyReadOnlyMethodsRequested`
- FAIL `genesisIsDevnet`
- FAIL `finalizedBlockhashObtained`
- FAIL `blockHeightIsSafeInteger`
- FAIL `messageFeeWithinReservedCap`
- FAIL `draftFieldsPreserved`
- FAIL `threeReadCallsOnly`
- PASS `noBroadcastAttempted`
- PASS `ephemeralInputSeedsCleared`
- `replay_status=401` — byte-identical replay denied by the durable one-time
  token store on the deployed runtime. PASS

Interpretation, stated strictly:

- PROVEN on the deployed Worker: the diagnostic route is reachable, the durable
  fail-closed authentication accepts exactly one signed request and denies both
  the unauthenticated request and the byte-identical replay; the endpoint is the
  pinned HTTPS devnet endpoint; no broadcast was attempted; ephemeral input seeds
  were cleared.
- NOT PROVEN: deployed-Worker RPC capability. Only ONE outbound read was made
  (`rpcCallCount=1`, expected 3) and the first read did not yield a devnet
  genesis value, so blockhash, block height, message fee and draft-preservation
  checks never ran. `onlyReadOnlyMethodsRequested` fails because fewer than the
  three expected read methods were observed. Genuine Worker RPC proof requires
  signed 200 with `ok=true`, all 10 checks and exactly 3 reads; that was NOT
  obtained.
- The failure is in the outbound network read from the deployed runtime, not in
  auth, not in the endpoint pin, and not in any broadcast path. Root cause is not
  yet diagnosed and must not be guessed; no value may be substituted from stored
  records.

`SIGNER_DIAGNOSTIC_ENABLED` was set back to `"false"` in the secret store
immediately after this evidence was captured (name and literal value only; caller
credentials never read or touched). Secret changes only take effect live after a
republish, so the live endpoint still serves the enabled configuration until
Codex publishes the disabled config. No further live polling was performed.

No funding, airdrop, broadcast, wallet key, provisioning activation, schema
application or mainnet was involved.

## Bounded transport metadata in the read-only RPC diagnostic

Purpose: diagnose the live failure (signed 200, ok=false, rpcCalls=1, checks 3/10)
without weakening opacity. Nothing about the provider is surfaced.

Added to `runReadOnlyRpcSelfCheck` and to the diagnostic response as `transport`:
`attemptCount`, `responseCount`, `statuses` (numeric HTTP statuses in request
order), `httpErrorCount`, `timedOut`, `transportFailed`, and a fixed-label
`classification` of `no_attempt | responded | http_error | timeout | transport_failure`.

Never included: response text or body, headers, the endpoint, any key, or any
provider error message. The HTTP adapter itself remains opaque and unchanged.

Classification tests (local mock transports only, no network call):
- `scripts/http-rpc-selftest.ts` — 89/89 PASS, including healthy `responded`
  (three 200s), `http_error` (503, status number only), `timeout` (AbortError,
  no status), `transport_failure` (TypeError, no status), malformed 200 body
  still `responded`, plus leak assertions: no provider error text, no endpoint,
  values are numbers/booleans and one fixed label.
- `scripts/rpc-diagnostic-selftest.ts` — 51/51 PASS, including served-report
  hygiene for the new field and outage classification.

Other suites unchanged and green: custody 45/45, wallet record 94/94, SDK smoke
9/9. `tsgo --noEmit` clean, `bun run build` PASS.

`SIGNER_DIAGNOSTIC_ENABLED` remains "false"; no live request was made in this
slice. No RPC compatibility on the deployed runtime is claimed and no wallet
readiness is claimed. No funding, airdrop, broadcast, schema application or
mainnet.

Source SHA before this slice: a1ea30acdfbe9a3b963456e870e7d9d947bd0adc (this
slice auto-committed on top).

## Isolated signer bridge receiver (SOURCE ONLY, DEFAULT DISABLED)

Ported from the Codex-reviewed public BRUH source at commit
`400fa34a5dff899091b646a6d172feda97e65dd0` on `codex/devnet-custody-core`
(`services/custody-signer/bridge-auth.ts`, `services/custody-signer/bridge-receiver.ts`,
`docs/decisions/0007-isolated-signer-bridge.md`). Only module filenames/import
paths were adapted; the upstream repository was not modified.

Modules:
- `src/lib/custody/bridge-auth.server.ts` — Ed25519 service authentication.
  Scheme `BRUH-DEVNET-BRIDGE-v1`; canonical binding of scheme, expected key ID,
  POST, one of two fixed paths (provision, membership — no withdrawal, export or
  arbitrary signing path), timestamp, 128-bit nonce and the exact raw-body
  SHA-256 digest. 8 KiB cap, 60 s freshness re-checked after the claim, atomic
  durable nonce claim with fixed 300 s retention, uniform opaque denial, nothing
  logged. Only the PUBLIC verification key is exchanged between projects: no
  shared HMAC secret, no elevated service key, and the diagnostic caller secret
  is never involved.
- `src/lib/wallets/bridge-receiver.server.ts` — fixed POST
  `/api/internal/custody/provision`, 8 KiB streamed cap, exact 4-key payload
  (`version: 1`, `telegram_init_data`, `telegram_chat_id`, `membership_approval`
  with approved/groupId/membershipId/telegramChatId/telegramUserId). One nonce
  claim precedes all Telegram, approval and vault work. The verified Telegram
  user must equal the signed approval's user; initData alone never proves group
  membership — the authority is BRUH's server-resolved non-banned membership
  snapshot plus the service signature. Responses are rebuilt from the exact
  frozen devnet public metadata shape; envelope fields, unfreezing and mainnet
  replies are refused, all responses are `no-store`, failures carry no text.
- `src/lib/wallets/provisioning.server.ts` — refactored: the post-authorization
  logic is now the shared `provisionVerifiedScope(scope, vault, store)` core.
  The existing HMAC + pinned-Telegram + membership-callback service delegates to
  it unchanged, and the bridge receiver reaches it only through a
  bridge-verified approval. There is no HMAC bypass and no auth-bypass flag. All
  record parsing, envelope structural validation, authenticated decryption
  (`vault.validate`), one-wallet-per-Telegram-identity, inconsistent-mapping
  refusal and first-writer-wins race behaviour are preserved.
- `src/routes/api/internal/custody/provision.ts` — DEFAULT DISABLED.
  `BRUH_BRIDGE_ENABLED` must be exactly "true" (otherwise 404). Fails closed
  with no fallback when `BRUH_BRIDGE_CALLER_KEY_ID`,
  `BRUH_BRIDGE_CALLER_PUBLIC_KEY` (pinned BRUH public key, 64 hex), the durable
  nonce store, the production wrapping key or the wallet store is absent. Names
  only; none of these is configured. Telegram uses the pinned production
  Ed25519 verifier.

Tests (offline):
- `scripts/bridge-receiver-selftest.ts` — 102/102 PASS. Disabled-by-default 404,
  happy path and exact public response shape, configuration failures, signature
  failures (other service key, key-ID substitution, cross-path signature, body
  tampering, stale/future timestamp, GET, unsigned), replay denial with exactly
  one nonce claim, payload contract (unknown version, extra fields, chat/user
  mismatch, non-canonical and out-of-range IDs, oversized initData, 8 KiB cap),
  mandatory Telegram binding, provisioning-result contract (no envelope fields,
  no unfrozen or mainnet reply, denial never becomes a 200), and bridge-verified
  approvals driven through the real shared core with an ephemeral wrapping key:
  idempotent repeat, refused remapped membership, concurrent approvals yielding
  one wallet, fail-closed on absent wrapping key/store.
- `scripts/bridge-gateway-contract-test.ts` — 51/51 PASS. Public-key-only
  exchange, path allowlist, canonical binding, header set, clock window with
  post-claim freshness, durable claim contract (exactly 300 s requested, no
  claim on a refused request), and payload envelope/cap.

Preserved suites, all green after the refactor: wallet provisioning 67/67,
wallet record/envelope 94/94, wallet SQL (PGlite) 164/164, custody/auth 45/45,
Telegram 27/27, nonce boundary 14/14, crypto probe 28/28, RPC client 89/89, RPC
diagnostic 51/51, SDK smoke 9/9. `tsgo --noEmit` clean, `bun run build` PASS.

Limitations: service signatures are ACTUAL ephemeral Ed25519 signatures, but
Telegram verification and membership approvals are fixtures — this is NOT real
Telegram, real BRUH membership or deployed-runtime proof. The route is not
enabled or configured, the wallet schema is still unapplied, no live
provisioning, no funds, no deposits, no signing, no broadcast, no mainnet. The
diagnostic kill switch remains "false".

Source SHA before this slice: fa1fca32b9863838f497a9c0ebf0e2ba760d110a (this
slice auto-committed on top).

## Bounded live RPC diagnostic — prepared (NOT PUBLISHED)

`scripts/live-rpc-diagnostic-probe.ts` now also prints the reviewed bounded
transport metadata for the signed request: `classification` (one of no_attempt |
responded | http_error | timeout | transport_failure), `attempts`, `responses`,
numeric `statuses`, `httpErrors`, `timedOut`, `transportFailed`. It asserts the
metadata is bounded (numbers, booleans and one fixed label only) and still
prints no raw body, header, endpoint, provider text, signature, nonce or secret.
Exactly three requests: unauthenticated denial, one signed check, byte-identical
replay denial. No polling.

`SIGNER_DIAGNOSTIC_ENABLED` set to "true" through the secure secret manager for
this single bounded trial (name and literal value only; the caller credentials
were not read or touched). It takes effect live only after a republish and goes
back to "false" immediately after the evidence is captured.

Nothing else changed: the wallet bridge route stays disabled and unconfigured
(`BRUH_BRIDGE_ENABLED` absent), no wallet enable flag, wallet store, wrapping
key, provisioning activation or schema application, no funds, no mainnet.
Production policy callbacks remain absent and fail closed.

Independently confirmed separately: the BRUH gateway-to-receiver contract passed
with actual Ed25519 service signatures and fixture Telegram/storage callbacks —
not real-account proof.

Suites after this slice: custody 45/45, Telegram 27/27, nonce boundary 14/14,
crypto probe 28/28, RPC diagnostic 51/51, RPC client 89/89, wallet provisioning
67/67, wallet record 94/94, bridge receiver 102/102, bridge gateway contract
51/51. `tsgo --noEmit` clean, `bun run build` PASS.

Source SHA before this slice: 01d3311198fe0a5010d5dd166e975355adaaed47 (this
slice auto-committed on top). Nothing was published by me.

## Live RPC diagnostic — single bounded trial (FAILED at the transport)

One attempt only, against the published deployment. Exactly three requests were
sent; no polling. Nothing but status, counts, booleans and the bounded transport
metadata was printed or recorded.

Exact captured evidence:
- `unauthenticated_status=401` — unauthenticated live POST denied.
- `signed_status=200` — one signed request served.
- `ok=false network=devnet readOnly=true broadcast=false rpcCalls=1 checks=3/10`
- transport: `classification=transport_failure attempts=1 responses=0 statuses=[]
  httpErrors=0 timedOut=false transportFailed=true`
- passed: `endpointPinnedHttps`, `noBroadcastAttempted`,
  `ephemeralInputSeedsCleared`, plus bounded-metadata, devnet and no-broadcast
  assertions.
- failed: `onlyReadOnlyMethodsRequested`, `genesisIsDevnet`,
  `finalizedBlockhashObtained`, `blockHeightIsSafeInteger`,
  `messageFeeWithinReservedCap`, `draftFieldsPreserved`, `threeReadCallsOnly`.
- `replay_status=401` — byte-identical replay denied by the durable one-time
  token store on the deployed runtime.

PROVEN on the deployed runtime: the route is reachable, the durable fail-closed
auth accepts exactly one signed request and denies both the unauthenticated
request and the byte-identical replay, the endpoint is the pinned devnet HTTPS
one, no broadcast was attempted, and the allocated seed buffers were cleared.

NOT PROVEN: deployed-runtime RPC capability. Classified only from the safe
metadata: one outbound attempt was made, zero responses were received, no HTTP
status was ever observed, and the abort deadline did not fire —
`classification=transport_failure`. No provider, network or configuration cause
is claimed or inferred; no error text exists in this evidence and none was
invented. `onlyReadOnlyMethodsRequested` and the remaining checks are false only
because the read sequence aborted before they were evaluated, not because a
write method was requested (`noBroadcastAttempted` stayed true and the
transport wrapper hard-fails on any non-read method).

`SIGNER_DIAGNOSTIC_ENABLED` set back to "false" immediately after this single
attempt through the secure secret manager (name and literal value only; caller
credentials never read or touched). It takes effect live only after Codex
publishes the shutdown; no further live request was made.

Unchanged: wallet bridge route disabled and unconfigured, no wallet enable flag,
store, wrapping key, provisioning activation or schema application, no funds, no
mainnet. Production policy callbacks remain absent and fail closed.

Source SHA of the published deployment under test:
6299faac295ca0367871dd54fe70501c16dcea2b (docs-only diff on top of the reviewed
01d3311198fe0a5010d5dd166e975355adaaed47). This evidence is committed on top.

## Host fetch receiver binding fix (SOURCE ONLY, DIAGNOSTIC STILL OFF)

Network policy is unchanged: same pinned endpoint, same three read methods, same
hard write-method denial, same caps, same opaque adapter, no fallback transport.

Change: both production defaults previously used an extracted, unbound `fetch`
reference (`transport: typeof fetch = fetch`) in `runReadOnlyRpcSelfCheck` and in
the `DevnetHttpSolRpc` constructor. Both now use an explicit arrow,
`(input, init) => globalThis.fetch(input, init)`, so the call keeps `globalThis`
as its receiver. Some Worker hosts reject a wrong receiver with
`TypeError: Illegal invocation`. This is a plausible root-cause match for the
failed live trial, but it is NOT claimed as the actual cause: only a further
bounded live trial can establish that.

The counting transport now also records a single fixed boolean,
`transport.illegalInvocation`, set only when the caught error is a `TypeError`
whose message is exactly "Illegal invocation". No raw error name, message, body,
header, endpoint or provider text is ever recorded or emitted; the trusted live
probe prints and bound-checks that boolean along with the other metadata.

Also in this slice:
- the bridge route returns 404 with `cache-control: no-store` from the disabled
  gate BEFORE constructing the durable nonce dependency or touching any store or
  key lookup;
- the `provisioning.server.ts` header comment is corrected: the only HTTP route
  importing it is the default-disabled, unconfigured bridge route, via the shared
  `provisionVerifiedScope` core.

Tests: `scripts/http-rpc-selftest.ts` 96/96 (up from 89), including a local
mocked branded host fetch that throws `TypeError("Illegal invocation")` unless
`this === globalThis` — both production defaults call it successfully with the
correct receiver, while an unbound extracted reference against the same host is
classified `transport_failure` with `illegalInvocation === true` and no raw error
text in the metadata. All other suites unchanged and green: custody 45/45,
Telegram 27/27, nonce boundary 14/14, crypto probe 28/28, RPC diagnostic 51/51,
wallet provisioning 67/67, wallet record 94/94, bridge receiver 102/102, bridge
gateway contract 51/51, wallet SQL PGlite PASS, SDK smoke PASS. `tsgo --noEmit`
clean, `bun run build` PASS. Every response in these suites is a local mock — no
network call was made and no live request was repeated.

`SIGNER_DIAGNOSTIC_ENABLED` stays "false" pending source review. No wallet enable
flag, schema application, wrapping key, provisioning activation, funds or
mainnet. Source SHA before this slice: 235cf4fa73ee20bbbf3c419d31b89133ce34e273
(this slice auto-committed on top). Nothing published by me.

## Bounded live RPC trial preparation (binding fix, 2026-09-14)

- Source under test: `1724e5cad1c94f95d47e24f24e40b48b4b09b05d` (explicit `globalThis.fetch` binding in both `runReadOnlyRpcSelfCheck` default transport and `DevnetHttpSolRpc` constructor default; no fallback; disabled gate returns 404 no-store before constructing nonce dependencies).
- `SIGNER_DIAGNOSTIC_ENABLED` set to `"true"` (name and literal value only; caller credentials untouched) for ONE bounded live trial. Takes effect live only after Codex republish; set back to `"false"` immediately after the single attempt, success or failure.
- Expected evidence: signed 200 with `ok=true`, 10/10 checks, exactly 3 reads, plus exact replay 401. A disabled 404 is NOT success proof.
- The binding fix is a plausible match for the observed live `transport_failure` (1 attempt, 0 responses, no timeout) but is NOT claimed as the confirmed cause until the bounded live trial verifies.
- No wallet flag, store, wrapping key, provisioning, schema application, funds or mainnet. No repeated live polls; secret changes need a republish.
- tsgo --noEmit clean; `bun run build` PASS at the SHA above.

## Bounded live RPC trial result (binding fix, 2026-09-14) — FAILURE, network reading still NOT proven

Deployment under test: published `1724e5cad1c94f95d47e24f24e40b48b4b09b05d` (explicit globalThis.fetch binding fix). Single attempt, no repeats.

Exact observed facts (nothing else logged):
- unauthenticated_status=401 (PASS)
- signed_status=200; ok=false; network=devnet; readOnly=true; broadcast=false; rpcCalls=1; checks=3/10
- transport: classification=transport_failure; attempts=1; responses=0; statuses=[]; httpErrors=0; timedOut=false; transportFailed=true; illegalInvocation=false
- passed checks: endpointPinnedHttps, noBroadcastAttempted, ephemeralInputSeedsCleared
- failed checks: onlyReadOnlyMethodsRequested, genesisIsDevnet, finalizedBlockhashObtained, blockHeightIsSafeInteger, messageFeeWithinReservedCap, draftFieldsPreserved, threeReadCallsOnly
- replay_status=401 (PASS — byte-identical replay denied on the deployed runtime)

Interpretation, bounded to safe metadata only:
- The explicit `globalThis.fetch` binding fix did NOT resolve the failure: `illegalInvocation=false`, so wrong-receiver is ruled out as the observed cause.
- The first fetch attempt fails with a transport-layer failure (no HTTP response, not a timeout). Root cause remains undiagnosed; no provider or error cause is invented. A plausible unverified hypothesis is egress policy on the deployed host, but that is NOT established fact.
- PROVEN live: route reachable; durable fail-closed auth accepts exactly one signed request; unauthenticated and replay denied; pinned HTTPS devnet endpoint; no broadcast; seeds cleared.
- NOT PROVEN: deployed-runtime RPC capability. No value may be substituted from stored records.

`SIGNER_DIAGNOSTIC_ENABLED` set back to `"false"` immediately after this single attempt (name and literal value only; caller credentials untouched). Takes effect live after Codex shutdown publish. No repeated polls.

## Diagnosed cause of the deployed-runtime read failure (source-only)

Evidence method: the outbound fetch options used by the reviewed reader were
replayed against an isolated, throwaway worker runtime in the build sandbox
(installed for this diagnosis only and removed afterwards). Only the sanitized
finding is recorded here; no raw error text, provider response, header, body or
credential was written to chat, logs, docs or commits.

Concrete, evidenced cause: this runtime **rejects `redirect: "error"` on an
outbound fetch with a `TypeError` before any request is made**. The identical
request with `redirect: "manual"` succeeded (HTTP 200), and an explicit
`AbortSignal` was accepted. That matches the live evidence exactly: 1 attempt,
0 responses, `timedOut=false`, `transportFailed=true`, and the first read never
reaching the provider. No provider ban, rate limit or credential problem is
implied, and none is claimed.

Fix (policy unchanged — redirects are still never followed): the adapter now
sends `redirect: "manual"` and rejects any 3xx response explicitly. Deviation
from the reviewed upstream source is documented in the adapter header.

Classifier correction: the failure classifier previously matched the exact
two-word string "Illegal invocation", so the real host message (which continues
past those words and may append a documentation URL) would have been missed.
It now derives a fixed enum, `failureFingerprint`, for KNOWN fingerprints only:
`none`, `illegal_invocation` (prefix match), `unsupported_redirect_mode`,
`outside_request_context`, `invalid_abort_signal`, `aborted`, `dns_failure`,
`connection_refused`, `tls_failure`, `type_error_other`, `unknown`. Raw name,
message, code, cause, URL, body, header and stack are never carried out. The
trusted probe prints the fingerprint and asserts it is one fixed enum member.

Tests: reader/classifier suite 119/119 (14 fingerprint cases including the long
real-host illegal-invocation message with docs URL, the redirect-mode rejection
end to end, and leak assertions), RPC diagnostic guards 51/51, bridge receiver
102/102, bridge contract 51/51, wallet record 94/94, wallet provisioning 67/67,
custody 45/45, nonce boundary 14/14, SDK smoke pass. Types clean, build passes.

Still NOT proven: deployed-runtime network reading. The fix is source-only,
`SIGNER_DIAGNOSTIC_ENABLED` stays `"false"`, no live attempt was made, and no
RPC compatibility or wallet readiness is claimed until a reviewed scoped probe
runs once. No wallet flag, schema, wrapping key, provisioning, funds or mainnet.
