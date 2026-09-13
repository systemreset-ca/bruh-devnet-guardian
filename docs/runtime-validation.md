# BRUH Devnet Signer — runtime validation record

Project: BRUH Devnet Signer (isolated backend and secret scope; separate from
Crypto Companion Bot and BlackBox.Farm).
Network: **devnet only**. No funding, no broadcast, no mainnet, no imported
keys, no production wrapping key.

## Commit

Validated at commit `ec846f79efd8bbddd83c66888abd4d3246127595`
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
- `src/lib/custody/nonce-store.server.ts` resolves the durable consumer and
  currently returns `null`, so any future authenticated caller is denied. No
  durable store implementation and no test fallback exist.
- The only in-memory nonce store lives in the test harness
  (`scripts/support/in-memory-nonce-store.ts`) and is never importable from
  production modules.

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
- **Real durable database integration is not deployed yet.** There is no nonce
  table, no schema and no durable store, so `getDurableNonceConsumer()` returns
  `null` and every authenticated request fails closed. Authentication cannot be
  used in production until a durable atomic nonce store (conditional insert on a
  unique nonce key, shared across instances) is deployed.
- No signing HTTP route, keys, secrets, funded activation or schema exist.

## Revision history / GitHub

This project can be connected to its **own separate repository** via
**Settings → GitHub → Connect to GitHub** in the project editor. Each Lovable
project maps to a distinct repository, so connecting BRUH Devnet Signer does not
affect or disconnect the BRUH (`bruhlegends`) repository connection.
