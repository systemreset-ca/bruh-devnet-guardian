# BRUH Devnet Guardian

Create a dedicated private development project named BRUH Devnet Signer, for the BRUH Telegram wallet service. This is a separate backend and secret scope from Crypto Companion Bot and BlackBox.Farm. Enable Lovable Cloud if available within the existing workspace plan; do not purchase upgrades. Start with a minimal operator status page that reveals no secrets or wallet information. No wallet funding, mainnet, signing endpoints, imported keys, or generated production secrets yet. First inspect the runtime and report support for server-side Solana web3.js 1.98.4, AES-256-GCM envelope encryption, secure secret generation/storage, and server-only HTTP routes. The reviewed implementation is in public GitHub systemreset-ca/bruhlegends draft PR 46, branch codex/devnet-custody-core. Do not modify that repository or reuse any BlackBox secrets. This project will host the isolated signer after compatibility and endpoint authentication are verified.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/fe274b3a-1273-4254-8b49-25d0be0f47df).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
