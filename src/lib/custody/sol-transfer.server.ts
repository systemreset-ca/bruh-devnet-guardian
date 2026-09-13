/**
 * Constrained devnet SOL transfer construction and signing.
 *
 * Pattern source (read-only reference, never modified):
 *   systemreset-ca/bruhlegends, draft PR 46, branch codex/devnet-custody-core,
 *   services/custody-signer/sol-transfer.ts
 *
 * Deliberately absent in this project: RPC adapter, fee probing, broadcast,
 * confirmation inspection, mainnet endpoints. This module can only ever build
 * ONE System-program SOL transfer — never arbitrary instruction bytes.
 */
import {
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import bs58 from "bs58";

export const DEVNET_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type SolTransferApproval = {
  walletId: string;
  groupId: string;
  membershipId: string;
  reservationId: string;
  network: "devnet";
  sender: string;
  recipient: string;
  reference: string;
  lamports: string;
  feeCapLamports: string;
  blockhash: string;
  lastValidBlockHeight: number;
};

export function buildSolTransfer(approval: SolTransferApproval): VersionedTransaction {
  if (
    approval.network !== "devnet" ||
    ![approval.reservationId, approval.walletId, approval.groupId, approval.membershipId].every(
      (value) => UUID.test(value),
    ) ||
    !/^[1-9][0-9]{0,15}$/.test(approval.lamports) ||
    !/^(0|[1-9][0-9]{0,6})$/.test(approval.feeCapLamports) ||
    BigInt(approval.lamports) + BigInt(approval.feeCapLamports) > 9_000_000_000_000_000n ||
    BigInt(approval.feeCapLamports) > 1_000_000n ||
    !Number.isSafeInteger(approval.lastValidBlockHeight) ||
    approval.lastValidBlockHeight < 0
  ) {
    throw new Error("Invalid devnet SOL approval.");
  }
  const sender = new PublicKey(approval.sender);
  const recipient = new PublicKey(approval.recipient);
  const reference = new PublicKey(approval.reference);
  new PublicKey(approval.blockhash);
  if (
    [recipient, reference, SystemProgram.programId].some((key) => key.equals(sender)) ||
    reference.equals(recipient) ||
    reference.equals(SystemProgram.programId)
  ) {
    throw new Error("Invalid SOL transfer destination/reference.");
  }
  const instruction = SystemProgram.transfer({
    fromPubkey: sender,
    toPubkey: recipient,
    lamports: BigInt(approval.lamports),
  });
  instruction.keys.push({ pubkey: reference, isSigner: false, isWritable: false });
  return new VersionedTransaction(
    new TransactionMessage({
      payerKey: sender,
      recentBlockhash: approval.blockhash,
      instructions: [instruction],
    }).compileToV0Message(),
  );
}

export type SignedSolTransfer = {
  reservationId: string;
  network: "devnet";
  signature: string;
  wireBase64: string;
  lastValidBlockHeight: number;
};

/** Called only inside the encrypted vault; never exposed as a public signer. */
export function signSolTransfer(
  seed: Uint8Array,
  approval: SolTransferApproval,
): SignedSolTransfer {
  const transaction = buildSolTransfer(approval);
  const keypair = Keypair.fromSeed(seed);
  try {
    if (keypair.publicKey.toBase58() !== approval.sender) throw new Error("Wrong wallet signer.");
    transaction.sign([keypair]);
    return {
      reservationId: approval.reservationId,
      network: "devnet",
      signature: bs58.encode(transaction.signatures[0]!),
      wireBase64: Buffer.from(transaction.serialize()).toString("base64"),
      lastValidBlockHeight: approval.lastValidBlockHeight,
    };
  } finally {
    keypair.secretKey.fill(0);
  }
}

/** Offline check that a signed record matches its approval byte-for-byte. No RPC. */
export function assertSignedMatchesApproval(
  record: SignedSolTransfer,
  approval: SolTransferApproval,
): VersionedTransaction {
  const transaction = VersionedTransaction.deserialize(Buffer.from(record.wireBase64, "base64"));
  const expected = buildSolTransfer(approval);
  if (
    record.network !== "devnet" ||
    record.reservationId !== approval.reservationId ||
    record.lastValidBlockHeight !== approval.lastValidBlockHeight ||
    !Buffer.from(transaction.message.serialize()).equals(
      Buffer.from(expected.message.serialize()),
    )
  ) {
    throw new Error("Signed transfer differs from reservation.");
  }
  return transaction;
}
