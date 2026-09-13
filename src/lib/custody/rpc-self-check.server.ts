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

/** Server-owned, explicit, pinned. Not configurable by any caller. */
export const DIAGNOSTIC_RPC_ENDPOINT = "https://api.devnet.solana.com";

const READ_ONLY_METHODS = new Set(["getGenesisHash", "getLatestBlockhash", "getFeeForMessage"]);
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
}

function uuid(): string {
  return crypto.randomUUID();
}

/**
 * @param transport injected only by tests; production uses global fetch.
 */
export async function runReadOnlyRpcSelfCheck(
  transport: typeof fetch = fetch,
): Promise<RpcSelfCheckReport> {
  const checks: Record<string, boolean> = {
    endpointPinnedHttps: false,
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
    return transport(input, init);
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
    const url = new URL(DIAGNOSTIC_RPC_ENDPOINT);
    checks["endpointPinnedHttps"] =
      url.protocol === "https:" && !url.username && !url.password && !url.hash;

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

    const rpc = new DevnetHttpSolRpc(DIAGNOSTIC_RPC_ENDPOINT, countingTransport);
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
  return {
    ok: passedCount === entries.length,
    network: "devnet",
    broadcast: false,
    rpcCallCount: calls,
    checkCount: entries.length,
    passedCount,
    checks,
  };
}
