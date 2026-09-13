# BRUH Devnet Signer — Phase 0 (operator status page + runtime verification)

Isolated project for the BRUH Telegram wallet service. Separate backend and secret scope from Crypto Companion Bot and BlackBox.Farm. No secrets, keys, funding, mainnet, or signing endpoints in this phase.

## Runtime compatibility findings (inspected, no changes made)

| Requirement | Status | Notes |
| --- | --- | --- |
| Server-side Solana web3.js 1.98.4 | Supported, with one caveat | Pure-JS + fetch-based; runs in the server runtime. Version must be pinned exactly (`1.98.4`, no `^`). Any native/Node-only add-on (e.g. token metadata tooling using node-gyp) must be avoided. Keypair/signing use `@noble/*` under the hood, which is edge-safe. |
| AES-256-GCM envelope encryption | Supported | Verified live: 32-byte key, 12-byte IV, 16-byte auth tag round-trip works via the platform crypto module. Web Crypto is also available as the preferred edge-safe path. |
| Secure secret generation and storage | Supported | Platform-managed encrypted secret store; random values can be minted server-side and never surfaced in chat or code. Values are exposed only as server-side environment variables, read inside handlers. |
| Server-only HTTP routes | Supported | Typed server functions for app-internal calls, plus raw HTTP routes for external callers. Both run server-side only; secrets never reach the browser bundle. |
| Runtime baseline | Node 22 in the workspace; Cloudflare-style Worker runtime in production | Worker runtime has no child processes and no real OS filesystem — relevant for later key-handling design. |

## Phase 0 scope

1. **Lovable Cloud** — enable it on this project within the existing plan (no purchases). This creates this project's own isolated backend and secret scope; nothing is shared with, or read from, BlackBox.Farm.
2. **Operator status page at `/`** — replaces the placeholder. Shows only:
   - project name, environment label (`devnet`), and build/commit-free version string
   - a static capability matrix (the table above, no live probing)
   - explicit "armed: NO" style posture flags: funding disabled, mainnet disabled, signing endpoints absent, no keys imported, no production secrets generated
   - reference note to the reviewed source: `systemreset-ca/bruhlegends`, draft PR 46, branch `codex/devnet-custody-core` (read-only reference; that repo is never modified)
   - no balances, addresses, key material, secret names/values, or RPC endpoints
3. **Design system** — dark operator/console aesthetic defined in `src/styles.css` as semantic tokens (no ad-hoc colors in components), monospace-forward typography, amber/green status accents. No purple.
4. **Head metadata** — unique title/description/og/twitter on `/`.
5. **No dependencies installed this phase.** `@solana/web3.js@1.98.4` is added only in the phase that first needs it, pinned exactly.

## Explicitly out of scope until separately approved

Wallet funding, mainnet configuration, any signing or key-derivation endpoint, importing existing keys, generating production secrets, database schema for custody, Telegram webhook wiring, and any reuse of BlackBox or Crypto Companion Bot secrets.

## Next phase (for a later approval)

Endpoint authentication design (shared-secret or bearer verification on the server routes) and an AES-256-GCM envelope-encryption module with a devnet-only test vector, before any keypair is ever created.
