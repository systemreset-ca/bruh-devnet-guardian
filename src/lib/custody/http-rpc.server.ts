/**
 * Devnet HTTP JSON-RPC client — adapted from the Codex-reviewed public BRUH
 * source `services/custody-signer/http-rpc.ts` at commit
 * 6ca44ab5060a8250b7df77f28091898a89f5874f (PR 46). Only import names/paths are
 * adapted to this signer; the reviewed logic is unchanged.
 *
 * Properties carried over deliberately:
 *  - No `Connection` construction and no WebSocket subscriptions (this Worker
 *    build cannot construct web3.js `Connection` at all).
 *  - Explicit server-owned HTTPS endpoint; no credentials, no userinfo, no hash.
 *  - Genesis hash pinned to devnet before any other use.
 *  - Finalized commitment for blockhash and message fee.
 *  - Exact signed bytes are re-derived and compared before any send.
 *  - 5 second abort, 128 KiB response cap, opaque provider errors, no automatic
 *    HTTP retries, no redirects.
 *
 * This class is NOT wired to wallets, provisioning or the bot. `broadcast` and
 * `inspect` exist for source parity with the reviewed original and are not
 * reachable from any diagnostic path.
 */
import { VersionedTransaction, PublicKey } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import bs58 from "bs58";
import {
  DEVNET_GENESIS,
  buildSolTransfer,
  type SolTransferApproval,
  type SignedSolTransfer,
} from "./sol-transfer.server";

type Signed = SignedSolTransfer;
export type SolTransferDraft = Omit<SolTransferApproval, "blockhash" | "lastValidBlockHeight">;

const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const integer = (v: unknown): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** Explicit server-owned endpoint, no Connection/WebSocket construction, no
 * automatic retries, no provider errors/credentials in diagnostics. */
export class DevnetHttpSolRpc {
  private id = 0;
  constructor(
    private readonly endpoint: string,
    private readonly transport: typeof fetch = fetch,
  ) {
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      throw new Error("Explicit HTTPS RPC required.");
    }
    if (url.protocol !== "https:" || url.username || url.password || url.hash)
      throw new Error("Explicit HTTPS RPC required.");
  }
  private async call(method: string, params: unknown[] = []): Promise<unknown> {
    const id = ++this.id;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5_000);
    try {
      const response = await this.transport(this.endpoint, {
        method: "POST",
        redirect: "error",
        signal: controller.signal,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      });
      if (!response.ok || !response.body) throw new Error();
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        size += next["value"].byteLength;
        if (size > 131_072) {
          await reader.cancel();
          throw new Error();
        }
        chunks.push(next["value"]);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      const parsed: unknown = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
      if (
        !object(parsed) ||
        parsed["jsonrpc"] !== "2.0" ||
        parsed["id"] !== id ||
        Object.hasOwn(parsed, "error") ||
        !Object.hasOwn(parsed, "result")
      )
        throw new Error();
      return parsed["result"];
    } catch {
      throw new Error("Custody RPC unavailable or invalid.");
    } finally {
      clearTimeout(timeout);
    }
  }
  async assertDevnetGenesis() {
    if ((await this.call("getGenesisHash")) !== DEVNET_GENESIS)
      throw new Error("Custody signer requires devnet.");
  }
  private async fee(approval: SolTransferApproval) {
    const tx = buildSolTransfer(approval);
    const result = await this.call("getFeeForMessage", [
      Buffer.from(tx.message.serialize()).toString("base64"),
      { commitment: "finalized" },
    ]);
    if (
      !object(result) ||
      !integer(result["value"]) ||
      BigInt(result["value"]) > BigInt(approval.feeCapLamports)
    )
      throw new Error("SOL fee unavailable or exceeds reserved cap.");
  }
  async prepare(approval: SolTransferDraft): Promise<SolTransferApproval> {
    await this.assertDevnetGenesis();
    const recent = await this.call("getLatestBlockhash", [{ commitment: "finalized" }]);
    if (
      !object(recent) ||
      !object(recent["value"]) ||
      typeof recent["value"]["blockhash"] !== "string" ||
      !integer(recent["value"]["lastValidBlockHeight"])
    )
      throw new Error("Invalid finalized blockhash.");
    const snapshot = {
      ...approval,
      blockhash: recent["value"]["blockhash"],
      lastValidBlockHeight: recent["value"]["lastValidBlockHeight"],
    };
    await this["fee"](snapshot);
    return snapshot;
  }
  async verifyFee(approval: SolTransferApproval) {
    await this.assertDevnetGenesis();
    await this["fee"](approval);
  }
  validateSigned(record: Signed, approval: SolTransferApproval) {
    const wire = Buffer.from(record.wireBase64, "base64");
    const tx = VersionedTransaction.deserialize(wire);
    const expected = buildSolTransfer(approval);
    if (
      wire.toString("base64") !== record.wireBase64 ||
      record.network !== "devnet" ||
      record.reservationId !== approval.reservationId ||
      record["lastValidBlockHeight"] !== approval["lastValidBlockHeight"] ||
      tx.signatures.length !== 1 ||
      record.signature !== bs58.encode(tx.signatures[0]!) ||
      !Buffer.from(tx.message.serialize()).equals(Buffer.from(expected.message.serialize())) ||
      !ed25519.verify(
        tx.signatures[0]!,
        tx.message.serialize(),
        new PublicKey(approval.sender).toBytes(),
      )
    )
      throw new Error("Signed transfer differs from reservation.");
    return tx;
  }
  async broadcast(record: Signed, approval: SolTransferApproval) {
    this.validateSigned(record, approval);
    await this.assertDevnetGenesis();
    const signature = await this.call("sendTransaction", [
      record.wireBase64,
      {
        encoding: "base64",
        skipPreflight: false,
        preflightCommitment: "finalized",
        maxRetries: 2,
      },
    ]);
    if (signature !== record.signature) throw new Error("RPC broadcast acknowledgment mismatch.");
    return record.signature;
  }
  async inspect(record: Signed, approval: SolTransferApproval) {
    const expected = this.validateSigned(record, approval);
    await this.assertDevnetGenesis();
    const result = await this.call("getTransaction", [
      record.signature,
      { encoding: "base64", commitment: "finalized", maxSupportedTransactionVersion: 0 },
    ]);
    if (result === null) return { state: "pending" as const };
    if (
      !object(result) ||
      !object(result["meta"]) ||
      !integer(result["slot"]) ||
      !integer(result["meta"]["fee"]) ||
      !Object.hasOwn(result["meta"], "err") ||
      BigInt(result["meta"]["fee"]) > BigInt(approval.feeCapLamports) ||
      !Array.isArray(result["transaction"]) ||
      result["transaction"].length !== 2 ||
      result["transaction"][1] !== "base64" ||
      typeof result["transaction"][0] !== "string"
    )
      return { state: "mismatch" as const };
    try {
      const bytes = Buffer.from(result["transaction"][0], "base64");
      if (
        bytes.toString("base64") !== result["transaction"][0] ||
        !bytes.equals(Buffer.from(expected.serialize()))
      )
        return { state: "mismatch" as const };
    } catch {
      return { state: "mismatch" as const };
    }
    return {
      state:
        result["meta"]["err"] === null
          ? ("confirmed_exact_transfer" as const)
          : ("finalized_failed" as const),
      feeLamports: String(result["meta"]["fee"]),
      slot: result["slot"],
    };
  }
}
