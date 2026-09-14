/**
 * Read-only devnet RPC self-check.
 *
 * Three JSON-RPC reads only: getGenesisHash, getLatestBlockhash (finalized) and
 * getFeeForMessage (finalized). It proves that the reviewed HTTP RPC client can
 * reach a pinned devnet endpoint and prepare a transfer snapshot within the
 * reserved fee cap.
 *
 * Hard constraints:
 *  - Endpoint is server-owned and pinned in source; no caller/client input,
 *    no arbitrary endpoint, no provider key (these three calls need none).
 *  - Sender/recipient/reference keys are ephemeral and memory-only. The check
 *    reports `ephemeralInputSeedsCleared`, which means exactly this: the seed
 *    buffers this module allocated as key input were overwritten with zeros.
 *    It is NOT a claim that all key material is erased from memory. JavaScript
 *    and the wallet SDK give no such guarantee: derived key objects, internal
 *    SDK copies, string values and garbage-collected or relocated buffers stay
 *    outside this module's control. Clearing input seeds is defence-in-depth,
 *    not proof of erasure.
 *  - No airdrop, no funding, no sendTransaction, no broadcast: the transport
 *    wrapper hard-fails if any write method is ever attempted.
 *  - Result is booleans and counts only: never an address, key byte, blockhash,
 *    signature, wire byte or provider response/error text.
 */
import { Keypair } from "@solana/web3.js";
import { DevnetHttpSolRpc, type SolTransferDraft } from "./http-rpc.server";
import {
  HELIUS_DEVNET_HOST,
  describeDevnetRpcConfig,
  devnetRpcEnvFromProcess,
  resolveDevnetRpcEndpoint,
  type DevnetRpcConfigReport,
  type DevnetRpcEnv,
} from "./rpc-endpoint.server";

const READ_ONLY_METHODS = new Set(["getGenesisHash", "getLatestBlockhash", "getFeeForMessage"]);

/** Fixed enum values only — never raw error text. */
export type TransportFailureFingerprint =
  | "none"
  | "illegal_invocation"
  | "unsupported_redirect_mode"
  | "outside_request_context"
  | "invalid_abort_signal"
  | "aborted"
  | "dns_failure"
  | "connection_refused"
  | "tls_failure"
  | "type_error_other"
  | "unknown";

const CAUSE_CODES: Record<string, TransportFailureFingerprint> = {
  ENOTFOUND: "dns_failure",
  EAI_AGAIN: "dns_failure",
  ECONNREFUSED: "connection_refused",
  ECONNRESET: "connection_refused",
  EPROTO: "tls_failure",
  ERR_TLS_CERT_ALTNAME_INVALID: "tls_failure",
  DEPTH_ZERO_SELF_SIGNED_CERT: "tls_failure",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "tls_failure",
  CERT_HAS_EXPIRED: "tls_failure",
};

/**
 * Internal-only inspection of the thrown outbound-fetch exception. It returns a
 * fixed enum member for known fingerprints and never returns, logs or stores the
 * raw name, message, code, cause, URL, body, header or stack.
 */
export function classifyTransportFailure(error: unknown): TransportFailureFingerprint {
  if (!(error && typeof error === "object")) return "unknown";
  const name = "name" in error ? String(error["name"]) : "";
  const message = "message" in error ? String(error["message"]) : "";
  const lower = message.toLowerCase();
  const code =
    "cause" in error && error["cause"] && typeof error["cause"] === "object"
      ? String((error["cause"] as { code?: unknown }).code ?? "")
      : "code" in error
        ? String(error["code"])
        : "";

  if (name === "AbortError" || name === "TimeoutError") return "aborted";
  // Prefix match: the real host message continues past the two words and may
  // append a documentation URL.
  if (lower.startsWith("illegal invocation")) return "illegal_invocation";
  if (lower.startsWith("invalid redirect value")) return "unsupported_redirect_mode";
  if (lower.includes("request outside of a request context")) return "outside_request_context";
  if (lower.includes("disallowed operation called within global scope"))
    return "outside_request_context";
  if (lower.includes("abortsignal")) return "invalid_abort_signal";
  const mapped = CAUSE_CODES[code];
  if (mapped) return mapped;
  if (name === "TypeError") return "type_error_other";
  return "unknown";
}
const FEE_CAP_LAMPORTS = "100000";

/**
 * Strictly bounded transport metadata: numeric HTTP statuses and failure-class
 * booleans only. It NEVER carries response text or body, headers, the endpoint,
 * a provider key, or any provider error message — the HTTP adapter stays opaque.
 */
export interface RpcTransportMetadata {
  attemptCount: number;
  responseCount: number;
  /** Numeric HTTP statuses in request order. No bodies, no headers. */
  statuses: number[];
  httpErrorCount: number;
  timedOut: boolean;
  transportFailed: boolean;
  /**
   * Fixed boolean only: true when the host rejected the fetch receiver
   * (`TypeError` whose message is exactly "Illegal invocation"). No raw error
   * name or message text is ever carried.
   */
  illegalInvocation: boolean;
  /**
   * Fixed enum for KNOWN failure fingerprints only. Derived internally from the
   * thrown exception, but NO raw name, message, code, cause, URL or stack text
   * is ever carried out of this module.
   */
  failureFingerprint: TransportFailureFingerprint;
  classification:
    | "no_attempt"
    | "responded"
    | "http_error"
    | "timeout"
    | "transport_failure";
}

export interface RpcSelfCheckReport {
  ok: boolean;
  network: "devnet";
  broadcast: false;
  rpcCallCount: number;
  checkCount: number;
  passedCount: number;
  checks: Record<string, boolean>;
  transport: RpcTransportMetadata;
  /** Presence and devnet-compatibility booleans only. Never a key or URL. */
  config: DevnetRpcConfigReport;
}

function uuid(): string {
  return crypto.randomUUID();
}

/**
 * @param transport injected only by tests; production uses the host's global
 * fetch through an explicit arrow so the call keeps `globalThis` as its
 * receiver. Some Worker hosts reject an extracted, unbound `fetch` with
 * `TypeError: Illegal invocation`. There is no fallback transport.
 */
export async function runReadOnlyRpcSelfCheck(
  transport: typeof fetch = (input, init) => globalThis.fetch(input, init),
  env: DevnetRpcEnv = devnetRpcEnvFromProcess(),
): Promise<RpcSelfCheckReport> {
  const config = describeDevnetRpcConfig(env);
  const checks: Record<string, boolean> = {
    endpointPinnedHttps: false,
    endpointHostIsDevnetHelius: false,
    onlyReadOnlyMethodsRequested: false,
    genesisIsDevnet: false,
    finalizedBlockhashObtained: false,
    blockHeightIsSafeInteger: false,
    messageFeeWithinReservedCap: false,
    draftFieldsPreserved: false,
    threeReadCallsOnly: false,
    noBroadcastAttempted: true,
    ephemeralInputSeedsCleared: false,
  };

  let calls = 0;
  const requested: string[] = [];
  // Bounded metadata only: statuses as numbers, failure classes as booleans.
  const statuses: number[] = [];
  let httpErrorCount = 0;
  let timedOut = false;
  let transportFailed = false;
  let illegalInvocation = false;
  let failureFingerprint: TransportFailureFingerprint = "none";
  const countingTransport: typeof fetch = async (input, init) => {
    calls += 1;
    let method = "";
    try {
      const parsed: unknown = JSON.parse(String(init?.body ?? "{}"));
      method =
        parsed && typeof parsed === "object" ? String((parsed as { method?: unknown }).method) : "";
    } catch {
      method = "";
    }
    requested.push(method);
    if (!READ_ONLY_METHODS.has(method)) {
      checks["noBroadcastAttempted"] = false;
      throw new Error("Read-only diagnostic refuses non-read RPC method.");
    }
    try {
      const response = await transport(input, init);
      statuses.push(response.status);
      if (!response.ok) httpErrorCount += 1;
      return response;
    } catch (error) {
      // Only the failure CLASS is recorded — never the error message or body.
      const fingerprint = classifyTransportFailure(error);
      if (failureFingerprint === "none") failureFingerprint = fingerprint;
      if (fingerprint === "illegal_invocation") illegalInvocation = true;
      if (fingerprint === "aborted") timedOut = true;
      else transportFailed = true;
      throw new Error("Custody RPC transport failure.");
    }
  };

  // Seeds are held locally so the input buffers can actually be overwritten:
  // web3.js
  // `Keypair.secretKey` hands back a copy, so zeroing that proves nothing.
  const seeds = [new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)];
  for (const seed of seeds) crypto.getRandomValues(seed);
  const [sender, recipient, reference] = seeds.map((seed) => Keypair.fromSeed(seed)) as [
    Keypair,
    Keypair,
    Keypair,
  ];
  try {
    // Server-only configuration: built internally from BRUH_DEVNET_API_KEY, or
    // an explicit SOLANA_RPC_URL that must itself be devnet Helius over HTTPS.
    // No public-RPC fallback, no mainnet key. Throws opaquely when unavailable.
    const endpoint = resolveDevnetRpcEndpoint(env);
    const url = new URL(endpoint);
    checks["endpointPinnedHttps"] =
      url.protocol === "https:" && !url.username && !url.password && !url.hash;
    checks["endpointHostIsDevnetHelius"] = url.hostname === HELIUS_DEVNET_HOST;

    const draft: SolTransferDraft = {
      walletId: uuid(),
      groupId: uuid(),
      membershipId: uuid(),
      reservationId: uuid(),
      network: "devnet",
      sender: sender.publicKey.toBase58(),
      recipient: recipient.publicKey.toBase58(),
      reference: reference.publicKey.toBase58(),
      lamports: "1",
      feeCapLamports: FEE_CAP_LAMPORTS,
    };

    const rpc = new DevnetHttpSolRpc(endpoint, countingTransport);
    // prepare() pins genesis, reads a finalized blockhash and checks the
    // message fee against the reserved cap. Any failure throws opaquely.
    const prepared = await rpc.prepare(draft);

    // Genesis and fee both passed inside prepare(), otherwise it would throw.
    checks["genesisIsDevnet"] = true;
    checks["messageFeeWithinReservedCap"] = true;
    checks["finalizedBlockhashObtained"] =
      typeof prepared.blockhash === "string" && prepared.blockhash.length >= 32;
    checks["blockHeightIsSafeInteger"] =
      Number.isSafeInteger(prepared.lastValidBlockHeight) && prepared.lastValidBlockHeight > 0;
    checks["draftFieldsPreserved"] =
      prepared.network === "devnet" &&
      prepared.reservationId === draft.reservationId &&
      prepared.sender === draft.sender &&
      prepared.recipient === draft.recipient &&
      prepared.reference === draft.reference &&
      prepared.lamports === draft.lamports &&
      prepared.feeCapLamports === draft.feeCapLamports;
    checks["onlyReadOnlyMethodsRequested"] = requested.every((m) => READ_ONLY_METHODS.has(m));
    checks["threeReadCallsOnly"] = calls === 3;
  } catch {
    // Opaque: provider errors and responses are never surfaced.
  } finally {
    for (const seed of seeds) seed.fill(0);
    checks["ephemeralInputSeedsCleared"] = seeds.every((seed) => seed.every((b) => b === 0));
  }

  const entries = Object.entries(checks);
  const passedCount = entries.filter(([, value]) => value === true).length;
  const classification: RpcTransportMetadata["classification"] = timedOut
    ? "timeout"
    : transportFailed
      ? "transport_failure"
      : httpErrorCount > 0
        ? "http_error"
        : statuses.length > 0
          ? "responded"
          : "no_attempt";
  return {
    ok: passedCount === entries.length,
    network: "devnet",
    broadcast: false,
    rpcCallCount: calls,
    checkCount: entries.length,
    passedCount,
    checks,
    transport: {
      attemptCount: calls,
      responseCount: statuses.length,
      statuses,
      httpErrorCount,
      timedOut,
      transportFailed,
      illegalInvocation,
      failureFingerprint,
      classification,
    },
  };
}
