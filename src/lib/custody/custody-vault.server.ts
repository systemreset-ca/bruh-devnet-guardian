/**
 * AES-256-GCM envelope custody vault (devnet only).
 *
 * Pattern source (read-only reference, never modified):
 *   systemreset-ca/bruhlegends, draft PR 46, branch codex/devnet-custody-core,
 *   src/lib/custody-vault.server.ts
 *
 * Constraints held in this project:
 *   - the wrapping key must be supplied by the caller; there is no env fallback,
 *     no database, no persistence and no public route
 *   - no raw seed export/import API
 *   - devnet only, and signing is limited to one constrained SOL transfer
 *   - JS cannot guarantee memory erasure; zeroing is best-effort defence only
 */
import { webcrypto } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import bs58 from "bs58";
import {
  buildSolTransfer,
  signSolTransfer,
  type SolTransferApproval,
} from "./sol-transfer.server";

const crypto = webcrypto as unknown as Crypto;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type CustodyIdentity = {
  walletId: string;
  groupId: string;
  membershipId: string;
  network: "devnet";
};

export type CustodyEnvelope = CustodyIdentity & {
  version: 1;
  address: string;
  wrappingKeyVersion: string;
  seedIv: string;
  encryptedSeed: string;
  wrappingIv: string;
  wrappedDataKey: string;
};

function bytes(value: string, length: number): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error("Invalid custody envelope.");
  const result = Uint8Array.from(Buffer.from(value, "base64"));
  if (result.length !== length || Buffer.from(result).toString("base64") !== value) {
    throw new Error("Invalid custody envelope.");
  }
  return result;
}

function identity(input: CustodyIdentity): CustodyIdentity {
  if (
    input.network !== "devnet" ||
    ![input.walletId, input.groupId, input.membershipId].every((value) => UUID.test(value))
  ) {
    throw new Error("Invalid devnet custody identity.");
  }
  return {
    walletId: input.walletId,
    groupId: input.groupId,
    membershipId: input.membershipId,
    network: "devnet",
  };
}

/** Additional authenticated data binds each ciphertext to its full scope. */
function aad(input: CustodyEnvelope, purpose: "seed" | "key"): Uint8Array<ArrayBuffer> {
  const scope = identity(input);
  if (
    input.version !== 1 ||
    !/^[a-zA-Z0-9._-]{1,64}$/.test(input.wrappingKeyVersion) ||
    bs58.decode(input.address).length !== 32
  ) {
    throw new Error("Invalid custody envelope.");
  }
  return Uint8Array.from(
    new TextEncoder().encode(
      JSON.stringify([
        "BRUH-custody-v1",
        purpose,
        scope.walletId,
        scope.groupId,
        scope.membershipId,
        scope.network,
        input.address,
        input.wrappingKeyVersion,
      ]),
    ),
  );
}

const b64 = (value: ArrayBuffer | Uint8Array) =>
  Buffer.from(value instanceof Uint8Array ? value : new Uint8Array(value)).toString("base64");

export class DevnetCustodyVault {
  constructor(
    private readonly wrappingKey: CryptoKey,
    private readonly keyVersion: string,
  ) {
    if (
      wrappingKey.type !== "secret" ||
      wrappingKey.algorithm.name !== "AES-GCM" ||
      (wrappingKey.algorithm as AesKeyAlgorithm).length !== 256 ||
      wrappingKey.extractable ||
      !wrappingKey.usages.includes("encrypt") ||
      !wrappingKey.usages.includes("decrypt") ||
      !/^[a-zA-Z0-9._-]{1,64}$/.test(keyVersion)
    ) {
      throw new Error("Invalid custody wrapping key.");
    }
  }

  async provision(input: CustodyIdentity): Promise<CustodyEnvelope> {
    const scope = identity(input);
    const seed = crypto.getRandomValues(new Uint8Array(32));
    try {
      return await this.seal(scope, seed);
    } finally {
      seed.fill(0);
    }
  }

  private async seal(
    scope: CustodyIdentity,
    seed: Uint8Array<ArrayBuffer>,
  ): Promise<CustodyEnvelope> {
    const dataKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    try {
      const key = await crypto.subtle.importKey("raw", dataKeyBytes, "AES-GCM", false, [
        "encrypt",
        "decrypt",
      ]);
      const seedIv = crypto.getRandomValues(new Uint8Array(12));
      const wrappingIv = crypto.getRandomValues(new Uint8Array(12));
      const envelope: CustodyEnvelope = {
        ...scope,
        version: 1,
        address: bs58.encode(ed25519.getPublicKey(seed)),
        wrappingKeyVersion: this.keyVersion,
        seedIv: b64(seedIv),
        wrappingIv: b64(wrappingIv),
        encryptedSeed: "",
        wrappedDataKey: "",
      };
      envelope.encryptedSeed = b64(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: seedIv, additionalData: aad(envelope, "seed") },
          key,
          seed,
        ),
      );
      envelope.wrappedDataKey = b64(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: wrappingIv, additionalData: aad(envelope, "key") },
          this.wrappingKey,
          dataKeyBytes,
        ),
      );
      return envelope;
    } finally {
      dataKeyBytes.fill(0);
    }
  }

  private async unseal(
    envelope: CustodyEnvelope,
    expected: CustodyIdentity,
  ): Promise<Uint8Array<ArrayBuffer>> {
    const scope = identity(expected);
    if (
      envelope.wrappingKeyVersion !== this.keyVersion ||
      Object.entries(scope).some(([key, value]) => envelope[key as keyof CustodyIdentity] !== value)
    ) {
      throw new Error("Custody envelope scope mismatch.");
    }
    let rawKey: Uint8Array<ArrayBuffer> | undefined;
    let seed: Uint8Array<ArrayBuffer> | undefined;
    try {
      rawKey = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: bytes(envelope.wrappingIv, 12),
            additionalData: aad(envelope, "key"),
          },
          this.wrappingKey,
          bytes(envelope.wrappedDataKey, 48),
        ),
      );
      const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
      seed = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: bytes(envelope.seedIv, 12),
            additionalData: aad(envelope, "seed"),
          },
          key,
          bytes(envelope.encryptedSeed, 48),
        ),
      );
      if (seed.length !== 32 || bs58.encode(ed25519.getPublicKey(seed)) !== envelope.address) {
        throw new Error();
      }
      return seed;
    } catch {
      seed?.fill(0);
      throw new Error("Custody envelope authentication failed.");
    } finally {
      rawKey?.fill(0);
    }
  }

  async validate(envelope: CustodyEnvelope, expected: CustodyIdentity): Promise<void> {
    const seed = await this.unseal(envelope, expected);
    seed.fill(0);
  }

  /** Constructs exactly one SOL transfer, never arbitrary bytes. No broadcast here. */
  async signSolTransfer(
    envelope: CustodyEnvelope,
    expected: CustodyIdentity,
    approval: SolTransferApproval,
  ) {
    buildSolTransfer(approval);
    if (
      approval.sender !== envelope.address ||
      Object.entries(identity(expected)).some(
        ([key, value]) => approval[key as keyof CustodyIdentity] !== value,
      )
    ) {
      throw new Error("Wrong wallet approval.");
    }
    const seed = await this.unseal(envelope, expected);
    try {
      return signSolTransfer(seed, approval);
    } finally {
      seed.fill(0);
    }
  }

  async rotate(
    envelope: CustodyEnvelope,
    expected: CustodyIdentity,
    replacement: DevnetCustodyVault,
  ): Promise<CustodyEnvelope> {
    const seed = await this.unseal(envelope, expected);
    try {
      return await replacement.seal(identity(expected), seed);
    } finally {
      seed.fill(0);
    }
  }
}

/**
 * Test-only wrapping key: generated non-extractable, memory-resident, never
 * persisted or exported. NOT a production key-management path.
 */
export async function createEphemeralWrappingKey(
  keyVersion = "ephemeral-test",
): Promise<DevnetCustodyVault> {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  return new DevnetCustodyVault(key, keyVersion);
}
