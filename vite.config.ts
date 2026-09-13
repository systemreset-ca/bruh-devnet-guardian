// @lovable.dev/vite-tanstack-config already includes the following — do NOT add them manually
// or the app will break with duplicate plugins:
//   - TanStack devtools (dev-only, first), tanstackStart, viteReact, tailwindcss, tsConfigPaths,
//     nitro (build-only using cloudflare as a default target), VITE_* env injection, @ path alias,
//     React/TanStack dedupe, error logger plugins, and sandbox detection (port/host/strictPort).
// You can pass additional config via defineConfig({ vite: { ... }, etc... }) if needed.
import { fileURLToPath } from "node:url";
import { defineConfig } from "@lovable.dev/vite-tanstack-config";

export default defineConfig({
  tanstackStart: {
    // Redirect TanStack Start's bundled server entry to src/server.ts (our SSR error wrapper).
    // nitro/vite builds from this
    server: { entry: "server" },
  },
  vite: {
    resolve: {
      alias: [
        // @solana/web3.js 1.x statically imports `rpc-websockets`, whose package
        // exports resolve only under node/browser conditions — not the worker
        // runtime, which fails the production build. The signer never opens a
        // websocket subscription, so point it at the WebSocket-standard browser
        // build, which the worker runtime resolves and bundles cleanly.
        {
          find: /^rpc-websockets$/,
          replacement: "rpc-websockets/dist/index.browser.mjs",
        },
      ],
    },
  },
});
