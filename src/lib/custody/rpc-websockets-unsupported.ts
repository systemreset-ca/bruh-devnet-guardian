/**
 * Build-time replacement for `rpc-websockets`.
 *
 * @solana/web3.js 1.x statically imports this package for `Connection`'s
 * websocket subscriptions. Its package exports resolve only under node/browser
 * conditions, so the real module cannot be bundled for the worker runtime.
 *
 * This signer never opens a subscription — it builds and signs offline and does
 * not broadcast — so the import is satisfied with throwing stubs. If any future
 * code path actually tries to open one, it fails loudly instead of silently
 * degrading.
 */
const unsupported = () => {
  throw new Error("Websocket RPC subscriptions are not supported in this signer runtime.");
};

export class CommonClient {
  constructor() {
    unsupported();
  }
}

export class Client extends CommonClient {}

export function WebSocket(): never {
  return unsupported() as never;
}

export default { CommonClient, Client, WebSocket };
