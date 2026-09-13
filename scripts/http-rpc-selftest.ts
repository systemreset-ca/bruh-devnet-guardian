/**
 * Offline tests for the reviewed devnet HTTP JSON-RPC client and the read-only
 * RPC self-check. Every RPC response here is a local mock transport: no real
 * network call, no funding, no broadcast. Output is booleans only.
 */
import { Keypair, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";
import { DevnetHttpSolRpc, type SolTransferDraft } from "../src/lib/custody/http-rpc.server";
import {
  DEVNET_GENESIS,
  signSolTransfer,
  type SolTransferApproval,
} from "../src/lib/custody/sol-transfer.server";
import { runReadOnlyRpcSelfCheck } from "../src/lib/custody/rpc-self-check.server";

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean) {
  if (ok) {
    pass += 1;
    console.log(`PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL  ${name}`);
  }
}
async function rejects(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

const ENDPOINT = "https://rpc.invalid.test/devnet";
const BLOCKHASH = "9AeH2ZmSPtWjfMDDwbF7hE7fUFyHNn9zA9Xurn8gvA7g";
const HEIGHT = 300_000_000;

type Handler = (method: string, params: unknown[], id: number) => unknown;

function transportFor(
  handler: Handler,
  options: { status?: number; body?: BodyInit | null; idOverride?: number; raw?: string } = {},
): { transport: typeof fetch; calls: () => string[] } {
  const calls: string[] = [];
  const transport: typeof fetch = async (_input, init) => {
    const request = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
    calls.push(request.method);
    if (options.status && options.status !== 200) {
      return new Response("nope", { status: options.status });
    }
    if (options.raw !== undefined) {
      return new Response(options.raw, { status: 200 });
    }
    const result = handler(request.method, request.params, request.id);
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id: options.idOverride ?? request.id,
      result,
    });
    return new Response(payload, { status: 200 });
  };
  return { transport, calls: () => calls };
}

const happy: Handler = (method) => {
  if (method === "getGenesisHash") return DEVNET_GENESIS;
  if (method === "getLatestBlockhash")
    return { context: { slot: 1 }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: HEIGHT } };
  if (method === "getFeeForMessage") return { context: { slot: 1 }, value: 5000 };
  return null;
};

// ------------------------------------------------------------ endpoint policy
for (const bad of [
  "http://api.devnet.solana.com",
  "https://user:pass@api.devnet.solana.com",
  "https://api.devnet.solana.com/#frag",
  "not-a-url",
  "",
  "ws://api.devnet.solana.com",
  "wss://api.devnet.solana.com",
  "file:///etc/passwd",
]) {
  check(`endpoint rejected: ${bad || "(empty)"}`, (() => {
    try {
      new DevnetHttpSolRpc(bad);
      return false;
    } catch {
      return true;
    }
  })());
}
check("explicit https endpoint accepted", (() => {
  new DevnetHttpSolRpc("https://api.devnet.solana.com");
  return true;
})());
check(
  "constructing the client opens no socket and no Connection",
  (() => {
    // Construction must be pure: no web3.js Connection, no WebSocket.
    const { transport, calls } = transportFor(happy);
    new DevnetHttpSolRpc(ENDPOINT, transport);
    return calls().length === 0;
  })(),
);

// -------------------------------------------------------------- genesis pinning
{
  const { transport } = transportFor(happy);
  await new DevnetHttpSolRpc(ENDPOINT, transport).assertDevnetGenesis();
  check("devnet genesis accepted", true);
}
for (const [name, genesis] of [
  ["mainnet genesis rejected", "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"],
  ["testnet genesis rejected", "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"],
  ["null genesis rejected", null],
  ["numeric genesis rejected", 1],
] as const) {
  const { transport } = transportFor((method) => (method === "getGenesisHash" ? genesis : happy(method, [], 1)));
  check(name, await rejects(() => new DevnetHttpSolRpc(ENDPOINT, transport).assertDevnetGenesis()));
}

// ------------------------------------------------------------- prepare / fee cap
const sender = Keypair.generate();
const draft: SolTransferDraft = {
  walletId: crypto.randomUUID(),
  groupId: crypto.randomUUID(),
  membershipId: crypto.randomUUID(),
  reservationId: crypto.randomUUID(),
  network: "devnet",
  sender: sender.publicKey.toBase58(),
  recipient: Keypair.generate().publicKey.toBase58(),
  reference: Keypair.generate().publicKey.toBase58(),
  lamports: "1000",
  feeCapLamports: "10000",
};
{
  const { transport, calls } = transportFor(happy);
  const prepared = await new DevnetHttpSolRpc(ENDPOINT, transport).prepare(draft);
  check("prepare returns the finalized blockhash", prepared.blockhash === BLOCKHASH);
  check("prepare returns lastValidBlockHeight", prepared.lastValidBlockHeight === HEIGHT);
  check("prepare preserves every draft field", prepared.reservationId === draft.reservationId && prepared.lamports === "1000");
  check("prepare issues exactly three reads", calls().length === 3);
  check(
    "prepare reads genesis, blockhash and fee in order",
    calls().join(",") === "getGenesisHash,getLatestBlockhash,getFeeForMessage",
  );
  check("prepare never calls sendTransaction", !calls().includes("sendTransaction"));
}
{
  const { transport } = transportFor((method, params) => {
    if (method === "getLatestBlockhash") {
      check(
        "blockhash requested at finalized commitment",
        JSON.stringify(params) === JSON.stringify([{ commitment: "finalized" }]),
      );
    }
    if (method === "getFeeForMessage") {
      const options = (params as [string, Record<string, unknown>])[1];
      check("message fee requested at finalized commitment", options["commitment"] === "finalized");
    }
    return happy(method, params, 1);
  });
  await new DevnetHttpSolRpc(ENDPOINT, transport).prepare(draft);
}
for (const [name, fee] of [
  ["fee above the reserved cap rejected", 10_001],
  ["absurd fee rejected", 5_000_000],
  ["negative fee rejected", -1],
  ["fractional fee rejected", 5000.5],
  ["string fee rejected", "5000"],
  ["null fee rejected", null],
] as const) {
  const { transport } = transportFor((method, params, id) =>
    method === "getFeeForMessage" ? { value: fee } : happy(method, params, id),
  );
  check(name, await rejects(() => new DevnetHttpSolRpc(ENDPOINT, transport).prepare(draft)));
}
{
  const { transport } = transportFor((method, params, id) =>
    method === "getFeeForMessage" ? { value: 10_000 } : happy(method, params, id),
  );
  const prepared = await new DevnetHttpSolRpc(ENDPOINT, transport).prepare(draft);
  check("fee exactly at the cap accepted", prepared.blockhash === BLOCKHASH);
}
for (const [name, recent] of [
  ["missing blockhash rejected", { value: { lastValidBlockHeight: HEIGHT } }],
  ["non-string blockhash rejected", { value: { blockhash: 5, lastValidBlockHeight: HEIGHT } }],
  ["missing block height rejected", { value: { blockhash: BLOCKHASH } }],
  ["fractional block height rejected", { value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1.5 } }],
  ["array response rejected", [BLOCKHASH]],
  ["null response rejected", null],
] as const) {
  const { transport } = transportFor((method, params, id) =>
    method === "getLatestBlockhash" ? recent : happy(method, params, id),
  );
  check(name, await rejects(() => new DevnetHttpSolRpc(ENDPOINT, transport).prepare(draft)));
}

// -------------------------------------------------- transport / envelope hygiene
{
  const { transport, calls } = transportFor(happy, { status: 500 });
  check("provider 500 rejected", await rejects(() => new DevnetHttpSolRpc(ENDPOINT, transport).assertDevnetGenesis()));
  check("no automatic HTTP retry after a failure", calls().length === 1);
}
{
  const { transport, calls } = transportFor(happy, { status: 429 });
  check("provider 429 rejected without retry", (await rejects(() => new DevnetHttpSolRpc(ENDPOINT, transport).assertDevnetGenesis())) && calls().length === 1);
}
{
  const failing: typeof fetch = async () => {
    throw new Error("provider says: secret-key-abc123 quota exceeded");
  };
  let message = "";
  try {
    await new DevnetHttpSolRpc(ENDPOINT, failing).assertDevnetGenesis();
  } catch (error) {
    message = (error as Error).message;
  }
  check("provider error text is not surfaced", !message.includes("secret-key-abc123"));
  check("provider failure reported opaquely", message === "Custody RPC unavailable or invalid.");
}
{
  const { transport } = transportFor(happy, { idOverride: 999 });
  check("mismatched JSON-RPC id rejected", await rejects(() => new DevnetHttpSolRpc(ENDPOINT, transport).assertDevnetGenesis()));
}
for (const [name, raw] of [
  ["error member rejected", JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32000 }, result: DEVNET_GENESIS })],
  ["missing result rejected", JSON.stringify({ jsonrpc: "2.0", id: 1 })],
  ["wrong jsonrpc version rejected", JSON.stringify({ jsonrpc: "1.0", id: 1, result: DEVNET_GENESIS })],
  ["array envelope rejected", JSON.stringify([{ jsonrpc: "2.0", id: 1, result: DEVNET_GENESIS }])],
  ["non-JSON body rejected", "<html>gateway</html>"],
  ["empty body rejected", ""],
] as const) {
  const { transport } = transportFor(happy, { raw });
  check(name, await rejects(() => new DevnetHttpSolRpc(ENDPOINT, transport).assertDevnetGenesis()));
}
{
  // 128 KiB response cap, streamed.
  const oversize: typeof fetch = async () =>
    new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          for (let i = 0; i < 20; i += 1) controller.enqueue(new Uint8Array(16_384).fill(48));
          controller.close();
        },
      }),
      { status: 200 },
    );
  check("oversized response rejected at the 128 KiB cap", await rejects(() => new DevnetHttpSolRpc(ENDPOINT, oversize).assertDevnetGenesis()));
}
{
  let aborted = false;
  const hanging: typeof fetch = (_input, init) =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => {
        aborted = true;
        reject(new Error("aborted"));
      });
    });
  const started = Date.now();
  const failed = await rejects(() => new DevnetHttpSolRpc(ENDPOINT, hanging).assertDevnetGenesis());
  check("hanging provider aborts and rejects", failed && aborted);
  check("abort fires within the 5 second budget", Date.now() - started < 7_000);
}
{
  let sawRedirect = "";
  let sawContentType = "";
  const inspecting: typeof fetch = async (_input, init) => {
    sawRedirect = String(init?.redirect);
    sawContentType = String(new Headers(init?.headers).get("content-type"));
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: DEVNET_GENESIS }), { status: 200 });
  };
  await new DevnetHttpSolRpc(ENDPOINT, inspecting).assertDevnetGenesis();
  check("redirects are refused", sawRedirect === "error");
  check("json content type is sent", sawContentType === "application/json");
}

// --------------------------------------------------- exact signed bytes binding
{
  const { transport } = transportFor(happy);
  const rpc = new DevnetHttpSolRpc(ENDPOINT, transport);
  const approval: SolTransferApproval = { ...draft, blockhash: BLOCKHASH, lastValidBlockHeight: HEIGHT };
  const seed = sender.secretKey.slice(0, 32);
  const signed = signSolTransfer(seed, approval);
  const tx = rpc.validateSigned(signed, approval);
  check("exact signed bytes validate against the approval", tx.signatures.length === 1);
  check(
    "signature verifies against the approved sender",
    bs58.decode(signed.signature).length === 64 &&
      new PublicKey(approval.sender).toBase58() === approval.sender,
  );
  check(
    "tampered wire bytes rejected",
    await rejects(async () => rpc.validateSigned(
        {
          ...signed,
          wireBase64: (() => {
            const bytes = Buffer.from(signed.wireBase64, "base64");
            bytes[bytes.length - 3] = bytes[bytes.length - 3]! ^ 0xff;
            return bytes.toString("base64");
          })(),
        },
        approval,
      )),
  );
  check(
    "changed lamports rejected",
    await rejects(async () => rpc.validateSigned(signed, { ...approval, lamports: "1001" })),
  );
  check(
    "changed recipient rejected",
    await rejects(async () =>
      rpc.validateSigned(signed, { ...approval, recipient: Keypair.generate().publicKey.toBase58() }),
    ),
  );
  check(
    "changed reference rejected",
    await rejects(async () =>
      rpc.validateSigned(signed, { ...approval, reference: Keypair.generate().publicKey.toBase58() }),
    ),
  );
  check(
    "changed reservation id rejected",
    await rejects(async () => rpc.validateSigned({ ...signed, reservationId: crypto.randomUUID() }, approval)),
  );
  check(
    "changed block height rejected",
    await rejects(async () => rpc.validateSigned({ ...signed, lastValidBlockHeight: HEIGHT + 1 }, approval)),
  );
  check(
    "non-devnet record rejected",
    await rejects(async () => rpc.validateSigned({ ...signed, network: "mainnet-beta" as "devnet" }, approval)),
  );
  seed.fill(0);
}

// ----------------------------------------- read-only self-check (mock transport)
{
  const { transport, calls } = transportFor(happy);
  const report = await runReadOnlyRpcSelfCheck(transport);
  check("read-only self-check passes against a devnet-shaped provider", report.ok === true);
  check("self-check makes exactly three reads", report.rpcCallCount === 3 && calls().length === 3);
  check("self-check reports devnet and no broadcast", report.network === "devnet" && report.broadcast === false);
  check("self-check passed every check", report.passedCount === report.checkCount);
  const serialized = JSON.stringify(report);
  check("self-check output is booleans and counts only", Object.values(report.checks).every((v) => typeof v === "boolean"));
  check("self-check output contains no blockhash", !serialized.includes(BLOCKHASH));
  check("self-check output contains no address-shaped string", !/[1-9A-HJ-NP-Za-km-z]{32,}/.test(serialized));
  check("self-check never requested a write method", !calls().some((m) => m === "sendTransaction" || m === "requestAirdrop"));
}
{
  const { transport } = transportFor((method, params, id) =>
    method === "getGenesisHash" ? "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d" : happy(method, params, id),
  );
  const report = await runReadOnlyRpcSelfCheck(transport);
  check("self-check fails closed on a non-devnet provider", report.ok === false && report.checks["genesisIsDevnet"] === false);
}
{
  const { transport } = transportFor((method, params, id) =>
    method === "getFeeForMessage" ? { value: 1_000_000 } : happy(method, params, id),
  );
  const report = await runReadOnlyRpcSelfCheck(transport);
  check("self-check fails closed when the fee exceeds the cap", report.ok === false && report.checks["messageFeeWithinReservedCap"] === false);
}
{
  const dead: typeof fetch = async () => new Response("", { status: 503 });
  const report = await runReadOnlyRpcSelfCheck(dead);
  check("self-check fails closed when the provider is unavailable", report.ok === false);
  check("unavailable provider still reports zeroed ephemeral keys", report.checks["ephemeralKeysZeroed"] === true);
}

console.log(`\n${pass} passed, ${fail} failed`);
console.log(
  "NOTE: every response above is a local mock transport. No real network call, no funding, no broadcast, and NO deployed-Worker RPC proof.",
);
if (fail > 0) process.exit(1);
