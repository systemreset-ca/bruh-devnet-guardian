/**
 * Server-only SDK compatibility smoke checks (devnet, offline).
 *
 * Purpose: prove that @solana/web3.js, @noble/curves, bs58 and the platform
 * Web Crypto AES-256-GCM primitives actually work in this runtime.
 *
 * Hard constraints held here:
 *   - every seed and encryption key is generated in memory for the single check
 *     and best-effort zeroed; nothing is written, persisted, returned or logged
 *   - no RPC, no funding, no broadcast, no mainnet, no imported keys
 *   - no public endpoint exposes this module
 *   - platform Web Crypto only; no native addons
 *   - the result is booleans and non-secret metadata only
 */
import { webcrypto } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import bs58 from "bs58";
import {
  Keypair,
  SystemInstruction,
  SystemProgram,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { buildSolTransfer, type SolTransferApproval } from "./sol-transfer.server";

const crypto = webcrypto as unknown as Crypto;

export type SdkSmokeReport = {
  network: "devnet";
  broadcast: false;
  checks: {
    ephemeralKeypairGenerated: boolean;
    aesGcmKeyGenerated: boolean;
    seedRoundTripsWithScopedAad: boolean;
    wrongAadRejected: boolean;
    transferHasSingleSystemInstruction: boolean;
    referenceIsReadonlyAndUnique: boolean;
    recipientMatches: boolean;
    lamportsMatch: boolean;
    ed25519SignatureVerified: boolean;
  };
  passed: boolean;
};

const scopedAad = (label: string) =>
  new TextEncoder().encode(
    JSON.stringify(["BRUH-devnet-signer-smoke-v1", label, "devnet", "seed"]),
  );

/** Runs the full offline smoke check. Resolves to booleans only. */
export async function runSdkCompatibilitySmoke(): Promise<SdkSmokeReport> {
  const checks: SdkSmokeReport["checks"] = {
    ephemeralKeypairGenerated: false,
    aesGcmKeyGenerated: false,
    seedRoundTripsWithScopedAad: false,
    wrongAadRejected: false,
    transferHasSingleSystemInstruction: false,
    referenceIsReadonlyAndUnique: false,
    recipientMatches: false,
    lamportsMatch: false,
    ed25519SignatureVerified: false,
  };

  const seed = crypto.getRandomValues(new Uint8Array(32));
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  let recovered: Uint8Array | undefined;
  let keypair: Keypair | undefined;

  try {
    keypair = Keypair.fromSeed(seed);
    checks.ephemeralKeypairGenerated =
      bs58.decode(keypair.publicKey.toBase58()).length === 32 &&
      Buffer.from(ed25519.getPublicKey(seed)).equals(Buffer.from(keypair.publicKey.toBytes()));

    const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
    checks.aesGcmKeyGenerated =
      rawKey.length === 32 &&
      key.algorithm.name === "AES-GCM" &&
      (key.algorithm as AesKeyAlgorithm).length === 256 &&
      !key.extractable;

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sealed = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: scopedAad("wallet-scope") },
      key,
      seed,
    );
    recovered = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: scopedAad("wallet-scope") },
        key,
        sealed,
      ),
    );
    checks.seedRoundTripsWithScopedAad =
      sealed.byteLength === seed.length + 16 && Buffer.from(recovered).equals(Buffer.from(seed));

    try {
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: scopedAad("other-scope") },
        key,
        sealed,
      );
    } catch {
      checks.wrongAadRejected = true;
    }

    // One constrained devnet SOL transfer with a readonly unique reference.
    const recipient = Keypair.generate().publicKey;
    const reference = Keypair.generate().publicKey;
    const approval: SolTransferApproval = {
      walletId: crypto.randomUUID(),
      groupId: crypto.randomUUID(),
      membershipId: crypto.randomUUID(),
      reservationId: crypto.randomUUID(),
      network: "devnet",
      sender: keypair.publicKey.toBase58(),
      recipient: recipient.toBase58(),
      reference: reference.toBase58(),
      lamports: "12345",
      feeCapLamports: "5000",
      blockhash: Keypair.generate().publicKey.toBase58(),
      lastValidBlockHeight: 1,
    };

    const transaction = buildSolTransfer(approval);
    transaction.sign([keypair]);

    const wire = VersionedTransaction.deserialize(transaction.serialize());
    const message = wire.message;
    const decompiled = TransactionMessage.decompile(message);
    const instruction = decompiled.instructions[0]!;

    checks.transferHasSingleSystemInstruction =
      decompiled.instructions.length === 1 &&
      instruction.programId.equals(SystemProgram.programId);

    const referenceIndex = message.staticAccountKeys.findIndex((k) => k.equals(reference));
    const uniqueKeys = new Set(message.staticAccountKeys.map((k) => k.toBase58()));
    checks.referenceIsReadonlyAndUnique =
      referenceIndex >= 0 &&
      uniqueKeys.size === message.staticAccountKeys.length &&
      !message.isAccountWritable(referenceIndex) &&
      !message.isAccountSigner(referenceIndex) &&
      instruction.keys.some((k) => k.pubkey.equals(reference) && !k.isWritable && !k.isSigner);

    const decoded = SystemInstruction.decodeTransfer(instruction);
    checks.recipientMatches = decoded.toPubkey.equals(recipient);
    checks.lamportsMatch = BigInt(decoded.lamports.toString()) === BigInt(approval.lamports);

    checks.ed25519SignatureVerified = ed25519.verify(
      wire.signatures[0]!,
      message.serialize(),
      keypair.publicKey.toBytes(),
    );
  } finally {
    seed.fill(0);
    rawKey.fill(0);
    recovered?.fill(0);
    keypair?.secretKey.fill(0);
  }

  return {
    network: "devnet",
    broadcast: false,
    checks,
    passed: Object.values(checks).every(Boolean),
  };
}
