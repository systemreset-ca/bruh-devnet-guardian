/**
 * Ephemeral server-runtime self-check. Memory-only: the wrapping key, data key
 * and seed are generated per call, never persisted, exported or logged.
 * No RPC, no funding, no broadcast. Returns booleans only — never key material,
 * never a custody address, never ciphertext.
 */
import { webcrypto } from "node:crypto";
import { Keypair, PublicKey } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import bs58 from "bs58";
import { createEphemeralWrappingKey, type CustodyIdentity } from "./custody-vault.server";
import { assertSignedMatchesApproval, type SolTransferApproval } from "./sol-transfer.server";

export type SelfCheckReport = {
  ok: boolean;
  runtime: "server";
  network: "devnet";
  checks: Record<string, boolean>;
  versions: { web3js: "1.98.4"; nobleCurves: "2.3.0"; bs58: "6.0.0" };
};

const identity: CustodyIdentity = {
  walletId: "11111111-1111-4111-8111-111111111111",
  groupId: "22222222-2222-4222-8222-222222222222",
  membershipId: "33333333-3333-4333-8333-333333333333",
  network: "devnet",
};

export async function runEphemeralSelfCheck(): Promise<SelfCheckReport> {
  const checks: Record<string, boolean> = {};

  const vault = await createEphemeralWrappingKey("runtime-probe");
  const envelope = await vault.provision(identity);
  checks["aesGcmEnvelopeSealed"] =
    Buffer.from(envelope.encryptedSeed, "base64").length === 48 &&
    Buffer.from(envelope.wrappedDataKey, "base64").length === 48 &&
    Buffer.from(envelope.seedIv, "base64").length === 12;

  await vault.validate(envelope, identity);
  checks["aesGcmEnvelopeAuthenticated"] = true;

  checks["aadScopeBindingEnforced"] = await failsAsExpected(() =>
    vault.validate(envelope, { ...identity, groupId: "55555555-5555-4555-8555-555555555555" }),
  );
  checks["tamperedCiphertextRejected"] = await failsAsExpected(() => {
    const raw = Buffer.from(envelope.encryptedSeed, "base64");
    raw[0] = raw[0]! ^ 0x01;
    return vault.validate({ ...envelope, encryptedSeed: raw.toString("base64") }, identity);
  });

  const approval: SolTransferApproval = {
    ...identity,
    reservationId: "44444444-4444-4444-8444-444444444444",
    sender: envelope.address,
    recipient: Keypair.generate().publicKey.toBase58(),
    reference: Keypair.generate().publicKey.toBase58(),
    lamports: "1000",
    feeCapLamports: "5000",
    blockhash: bs58.encode(webcrypto.getRandomValues(new Uint8Array(32))),
    lastValidBlockHeight: 123456,
  };

  const signed = await vault.signSolTransfer(envelope, identity, approval);
  const transaction = assertSignedMatchesApproval(signed, approval);
  checks["solTransferSignedOffline"] = bs58.decode(signed.signature).length === 64;
  checks["ed25519SignatureVerifies"] = ed25519.verify(
    bs58.decode(signed.signature),
    transaction.message.serialize(),
    new PublicKey(envelope.address).toBytes(),
  );
  checks["singleSystemTransferInstruction"] =
    transaction.message.compiledInstructions.length === 1;
  checks["senderMismatchRejected"] = await failsAsExpected(() =>
    vault.signSolTransfer(envelope, identity, {
      ...approval,
      sender: Keypair.generate().publicKey.toBase58(),
    }),
  );
  checks["nonDevnetRejected"] = await failsAsExpected(() =>
    vault.signSolTransfer(envelope, identity, {
      ...approval,
      network: "mainnet-beta" as unknown as "devnet",
    }),
  );

  return {
    ok: Object.values(checks).every(Boolean),
    runtime: "server",
    network: "devnet",
    checks,
    versions: { web3js: "1.98.4", nobleCurves: "2.3.0", bs58: "6.0.0" },
  };
}

async function failsAsExpected(fn: () => unknown | Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}
