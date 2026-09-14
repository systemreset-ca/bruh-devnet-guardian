/**
 * Server-only devnet RPC endpoint configuration.
 *
 * Hard rules:
 *  - The endpoint is built internally from BRUH_DEVNET_API_KEY as
 *    `https://devnet.helius-rpc.com/?api-key=<key>`. The key value is never
 *    logged, returned, embedded in source or surfaced in any report.
 *  - An optional SOLANA_RPC_URL override is accepted ONLY when it is HTTPS,
 *    its host is exactly `devnet.helius-rpc.com`, and it carries no userinfo
 *    and no fragment. Anything else (mainnet host, other provider, http, ws,
 *    credentials in the URL) fails closed.
 *  - There is NO fallback to a public RPC endpoint and NO use of
 *    BRUH_MAINNET_API_KEY — this module never reads that name at all.
 *  - Devnet genesis is additionally proven at call time by the HTTP adapter
 *    (`assertDevnetGenesis`) before any other RPC use.
 *  - Reports carry booleans only: presence and devnet compatibility.
 */

export const HELIUS_DEVNET_HOST = "devnet.helius-rpc.com";

/** Loose shape check only; never echoed. */
const API_KEY = /^[A-Za-z0-9._-]{8,128}$/;

export interface DevnetRpcEnv {
  /** BRUH_DEVNET_API_KEY */
  devnetApiKey?: string | undefined;
  /** SOLANA_RPC_URL (optional explicit override) */
  rpcUrl?: string | undefined;
}

export interface DevnetRpcConfigReport {
  devnetApiKeyPresent: boolean;
  devnetApiKeyWellFormed: boolean;
  explicitRpcUrlPresent: boolean;
  explicitRpcUrlDevnetCompatible: boolean;
  endpointResolved: boolean;
  /** Fixed: the mainnet key is never read by this signer. */
  mainnetKeyUsed: false;
  /** Fixed: no public-RPC or mainnet fallback exists. */
  publicRpcFallbackUsed: false;
}

function urlDevnetCompatible(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    url.hostname === HELIUS_DEVNET_HOST &&
    !url.username &&
    !url.password &&
    !url.hash
  );
}

/**
 * Returns the endpoint to use, or throws an opaque error. The returned string
 * contains the API key and must NEVER be logged, reported or returned to a
 * caller — it is passed directly into the HTTP adapter only.
 */
export function resolveDevnetRpcEndpoint(env: DevnetRpcEnv): string {
  const key = typeof env.devnetApiKey === "string" ? env.devnetApiKey.trim() : "";
  if (!API_KEY.test(key)) throw new Error("Devnet RPC configuration unavailable.");
  const override = typeof env.rpcUrl === "string" ? env.rpcUrl.trim() : "";
  if (override) {
    if (!urlDevnetCompatible(override)) throw new Error("Devnet RPC configuration unavailable.");
    return override;
  }
  return `https://${HELIUS_DEVNET_HOST}/?api-key=${key}`;
}

/** Booleans only — never the key, the URL or any part of either. */
export function describeDevnetRpcConfig(env: DevnetRpcEnv): DevnetRpcConfigReport {
  const key = typeof env.devnetApiKey === "string" ? env.devnetApiKey.trim() : "";
  const override = typeof env.rpcUrl === "string" ? env.rpcUrl.trim() : "";
  const wellFormed = API_KEY.test(key);
  const overrideOk = override ? urlDevnetCompatible(override) : false;
  return {
    devnetApiKeyPresent: key.length > 0,
    devnetApiKeyWellFormed: wellFormed,
    explicitRpcUrlPresent: override.length > 0,
    explicitRpcUrlDevnetCompatible: overrideOk,
    endpointResolved: wellFormed && (!override || overrideOk),
    mainnetKeyUsed: false,
    publicRpcFallbackUsed: false,
  };
}

/** Server-side environment read; values never leave this module. */
export function devnetRpcEnvFromProcess(): DevnetRpcEnv {
  return {
    devnetApiKey: process.env["BRUH_DEVNET_API_KEY"],
    rpcUrl: process.env["SOLANA_RPC_URL"],
  };
}
