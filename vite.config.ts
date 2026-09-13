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
        // @solana/web3.js 1.x statically imports `rpc-websockets` for
        // Connection's subscriptions. Its package exports resolve only under
        // node/browser conditions, so it cannot be bundled for the worker
        // runtime and fails the production build. This signer never opens a
        // subscription, so the import is satisfied with throwing stubs.
        {
          find: /^rpc-websockets$/,
          replacement: fileURLToPath(
            new URL("./src/lib/custody/rpc-websockets-unsupported.ts", import.meta.url),
          ),
        },
      ],
    },
  },
});
