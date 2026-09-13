# BRUH Devnet Signer — runtime validation record

Project: BRUH Devnet Signer (isolated backend and secret scope; separate from
Crypto Companion Bot and BlackBox.Farm).
Network: **devnet only**. No funding, no broadcast, no mainnet, no imported
keys, no production wrapping key.

## Commit

Validated at commit `5f5affcd0f3d0460acb3ae77c0ab7550d25773fa`
(run date: 2026-09-13 UTC).

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

## Production build

`bun run build` — **PASS**, built in 387 ms, nitro output generated
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

**34 passed, 0 failed** (envelope structure, authentication, AAD scope binding,
foreign-key and extractable-key rejection, rotation, offline signature
verification, sender / zero-lamport / fee-cap / mainnet / recipient-mismatch /
tampered-record rejections, and the fail-closed request-auth suite: replay,
missing or short secret, body-digest binding, clock skew, wrong secret, path and
method binding, missing headers, oversized body).

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
- The SDK smoke module is intentionally not exposed as an HTTP endpoint.

## Revision history / GitHub

This project can be connected to its **own separate repository** via
**Settings → GitHub → Connect to GitHub** in the project editor. Each Lovable
project maps to a distinct repository, so connecting BRUH Devnet Signer does not
affect or disconnect the BRUH (`bruhlegends`) repository connection.
