/**
 * Ephemeral, memory-only self-test for the devnet signer slice.
 *
 * All seeds, data keys and wrapping keys are generated per run, kept in memory
 * and discarded. Nothing is funded, persisted or broadcast. No RPC calls.
 */
import { webcrypto } from "node:crypto";
import { Keypair, PublicKey, VersionedTransaction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import bs58 from "bs58";
import {
  createEphemeralWrappingKey,
  DevnetCustodyVault,
  type CustodyEnvelope,
  type CustodyIdentity,
} from "../src/lib/custody/custody-vault.server";
import {
  assertSignedMatchesApproval,
  buildSolTransfer,
  type SolTransferApproval,
} from "../src/lib/custody/sol-transfer.server";
import {
  HEADER_KEY_ID,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  bodyDigestHex,
  canonicalString,
  newNonce,
  signCanonical,
  verifySignerRequest,
  type NonceConsumer,
} from "../src/lib/custody/request-auth.server";
import {
  createFailingNonceStore,
  createInMemoryNonceStore,
} from "./support/in-memory-nonce-store";

let pass = 0;
let fail = 0;
function check(name: string, condition: boolean) {
  if (condition) {
    pass += 1;
    console.log(`PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL  ${name}`);
  }
}
async function rejects(name: string, fn: () => unknown | Promise<unknown>) {
  try {
    await fn();
    check(name, false);
  } catch {
    check(name, true);
  }
}

const identity: CustodyIdentity = {
  walletId: "11111111-1111-4111-8111-111111111111",
  groupId: "22222222-2222-4222-8222-222222222222",
  membershipId: "33333333-3333-4333-8333-333333333333",
  network: "devnet",
};

function approvalFor(sender: string): SolTransferApproval {
  return {
    ...identity,
    reservationId: "44444444-4444-4444-8444-444444444444",
    sender,
    recipient: Keypair.generate().publicKey.toBase58(),
    reference: Keypair.generate().publicKey.toBase58(),
    lamports: "1000",
    feeCapLamports: "5000",
    blockhash: bs58.encode(webcrypto.getRandomValues(new Uint8Array(32))),
    lastValidBlockHeight: 123456,
  };
}

async function main() {
  console.log(`node ${process.version}`);
  console.log("--- AES-256-GCM envelope ---");

  const vault = await createEphemeralWrappingKey("selftest-v1");
  const envelope = await vault.provision(identity);
  check("envelope version is 1", envelope.version === 1);
  check("address is a 32-byte ed25519 key", bs58.decode(envelope.address).length === 32);
  check("seed IV is 12 bytes", Buffer.from(envelope.seedIv, "base64").length === 12);
  check(
    "ciphertexts carry 16-byte GCM tags",
    Buffer.from(envelope.encryptedSeed, "base64").length === 48 &&
      Buffer.from(envelope.wrappedDataKey, "base64").length === 48,
  );
  check("no plaintext seed field on envelope", !("seed" in envelope));
  await vault.validate(envelope, identity);
  check("valid envelope authenticates", true);

  await rejects("tampered ciphertext rejected", () => {
    const bad = { ...envelope, encryptedSeed: flipByte(envelope.encryptedSeed) };
    return vault.validate(bad as CustodyEnvelope, identity);
  });
  await rejects("scope mismatch rejected (AAD binding)", () =>
    vault.validate(envelope, { ...identity, groupId: "55555555-5555-4555-8555-555555555555" }),
  );
  await rejects("foreign wrapping key cannot unseal", async () => {
    const other = await createEphemeralWrappingKey("selftest-v1");
    return other.validate(envelope, identity);
  });
  await rejects("extractable wrapping key rejected", async () => {
    const weak = await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    return new DevnetCustodyVault(weak as CryptoKey, "selftest-v1");
  });

  const rotated = await createEphemeralWrappingKey("selftest-v2");
  const rewrapped = await vault.rotate(envelope, identity, rotated);
  check("rotation preserves address", rewrapped.address === envelope.address);
  check("rotation changes ciphertext", rewrapped.encryptedSeed !== envelope.encryptedSeed);

  console.log("--- keypair + constrained SOL transfer signing (no broadcast) ---");
  const approval = approvalFor(envelope.address);
  const signed = await vault.signSolTransfer(envelope, identity, approval);
  check("signature is 64 bytes", bs58.decode(signed.signature).length === 64);
  const tx = assertSignedMatchesApproval(signed, approval);
  check("signed wire matches approval message", tx instanceof VersionedTransaction);
  const verified = ed25519.verify(
    bs58.decode(signed.signature),
    tx.message.serialize(),
    new PublicKey(envelope.address).toBytes(),
  );
  check("ed25519 signature verifies against custody address", verified);
  check(
    "message has exactly one instruction (System transfer + reference)",
    tx.message.compiledInstructions.length === 1 &&
      tx.message.compiledInstructions[0]!.accountKeyIndexes.length === 3,
  );

  await rejects("sender mismatch rejected", () =>
    vault.signSolTransfer(envelope, identity, approvalFor(Keypair.generate().publicKey.toBase58())),
  );
  await rejects("zero lamports rejected", () =>
    vault.signSolTransfer(envelope, identity, { ...approval, lamports: "0" }),
  );
  await rejects("fee cap above 1_000_000 lamports rejected", () =>
    vault.signSolTransfer(envelope, identity, { ...approval, feeCapLamports: "2000000" }),
  );
  await rejects("mainnet/other network rejected", () =>
    vault.signSolTransfer(envelope, identity, {
      ...approval,
      network: "mainnet-beta" as unknown as "devnet",
    }),
  );
  await rejects("recipient equal to sender rejected", () =>
    buildSolTransfer({ ...approval, recipient: approval.sender }),
  );
  await rejects("tampered signed record rejected offline", () =>
    assertSignedMatchesApproval(signed, { ...approval, lamports: "2000" }),
  );

  console.log("--- fail-closed request authentication ---");
  const nonceStore = createInMemoryNonceStore();
  const consumeNonce = nonceStore.consume;
  const secret = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("hex");
  const keyId = "selftest";
  const path = "/api/public/signer/selftest";
  const body = JSON.stringify({ probe: true });

  const sign = (opts?: {
    ts?: string;
    nonce?: string;
    body?: string;
    secret?: string;
    keyId?: string;
    signedKeyId?: string;
  }) => {
    const ts = opts?.ts ?? String(Date.now());
    const nonce = opts?.nonce ?? newNonce();
    const payload = opts?.body ?? body;
    const signature = signCanonical(
      opts?.secret ?? secret,
      canonicalString({
        keyId: opts?.signedKeyId ?? opts?.keyId ?? keyId,
        method: "POST",
        path,
        timestamp: ts,
        nonce,
        bodyDigestHex: bodyDigestHex(payload),
      }),
    );
    return {
      headers: new Headers({
        [HEADER_TIMESTAMP]: ts,
        [HEADER_NONCE]: nonce,
        [HEADER_SIGNATURE]: signature,
        [HEADER_KEY_ID]: opts?.keyId ?? keyId,
      }),
      rawBody: payload,
    };
  };
  const verify = (
    req: { headers: Headers; rawBody: string },
    overrides?: {
      secret?: string | undefined;
      expectedKeyId?: string | undefined;
      consumeNonce?: NonceConsumer | null;
      method?: string;
      path?: string;
      rawBody?: string;
    },
  ) =>
    verifySignerRequest({
      method: overrides?.method ?? "POST",
      path: overrides?.path ?? path,
      headers: req.headers,
      rawBody: overrides?.rawBody ?? req.rawBody,
      secret: overrides && "secret" in overrides ? overrides.secret : secret,
      expectedKeyId:
        overrides && "expectedKeyId" in overrides ? overrides.expectedKeyId : keyId,
      consumeNonce:
        overrides && "consumeNonce" in overrides ? overrides.consumeNonce : consumeNonce,
    });

  const good = sign();
  check("valid signed request accepted", (await verify(good)).ok);
  const replay = await verify(good);
  check("replayed nonce rejected", !replay.ok && replay.reason === "replayed_nonce");

  const noSecret = await verify(sign(), { secret: undefined });
  check("missing caller secret rejects", !noSecret.ok && noSecret.reason === "secret_unavailable");

  const shortSecret = await verify(sign(), { secret: "tooshort" });
  check("short secret rejects", !shortSecret.ok && shortSecret.reason === "secret_unavailable");

  const noKeyIdConfigured = await verify(sign(), { expectedKeyId: undefined });
  check(
    "missing configured expected key ID rejects",
    !noKeyIdConfigured.ok && noKeyIdConfigured.reason === "config_unavailable",
  );

  const substitutedKeyId = await verify(sign({ keyId: "attacker-key" }));
  check(
    "caller-supplied key ID differing from expected rejected",
    !substitutedKeyId.ok && substitutedKeyId.reason === "unknown_key_id",
  );

  const keyIdNotBound = await verify(sign({ signedKeyId: "other-key" }));
  check(
    "expected key ID bound into HMAC canonical input",
    !keyIdNotBound.ok && keyIdNotBound.reason === "bad_signature",
  );

  const noStore = await verify(sign(), { consumeNonce: null });
  check(
    "missing durable nonce store rejects (no in-memory fallback)",
    !noStore.ok && noStore.reason === "nonce_store_unavailable",
  );

  const storeOutage = await verify(sign(), { consumeNonce: createFailingNonceStore() });
  check(
    "nonce store outage fails closed",
    !storeOutage.ok && storeOutage.reason === "nonce_store_unavailable",
  );

  const concurrentNonce = newNonce();
  const concurrentAttempts = await Promise.all([
    verify(sign({ nonce: concurrentNonce })),
    verify(sign({ nonce: concurrentNonce })),
    verify(sign({ nonce: concurrentNonce })),
  ]);
  check(
    "concurrent same-nonce attempts accept exactly one",
    concurrentAttempts.filter((r) => r.ok).length === 1 &&
      concurrentAttempts
        .filter((r) => !r.ok)
        .every((r) => !r.ok && r.reason === "replayed_nonce"),
  );

  const tamperedBody = sign();
  const digestFail = await verify(tamperedBody, {
    rawBody: JSON.stringify({ probe: false }),
  });
  check("body digest binding rejects altered body", !digestFail.ok);

  const stale = await verify(sign({ ts: String(Date.now() - 5 * 60_000) }));
  check("stale timestamp rejected", !stale.ok && stale.reason === "stale_timestamp");

  const future = await verify(sign({ ts: String(Date.now() + 5 * 60_000) }));
  check("far-future timestamp rejected", !future.ok && future.reason === "stale_timestamp");

  const wrongKey = await verify(
    sign({
      secret: Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("hex"),
    }),
  );
  check("wrong caller secret rejected", !wrongKey.ok && wrongKey.reason === "bad_signature");

  const wrongPath = await verify(sign(), { path: "/api/public/signer/other" });
  check("path binding enforced", !wrongPath.ok && wrongPath.reason === "bad_signature");

  const wrongMethod = await verify(sign(), { method: "GET" });
  check("method binding enforced", !wrongMethod.ok && wrongMethod.reason === "bad_signature");

  const missingHeaders = await verify({ headers: new Headers(), rawBody: body });
  check(
    "missing auth headers rejected",
    !missingHeaders.ok && missingHeaders.reason === "malformed_request",
  );

  const oversized = await verify(sign(), { rawBody: "x".repeat(64 * 1024 + 1) });
  check("oversized body rejected", !oversized.ok && oversized.reason === "body_too_large");

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
}

function flipByte(base64: string): string {
  const raw = Buffer.from(base64, "base64");
  raw[0] = raw[0]! ^ 0x01;
  return raw.toString("base64");
}

await main();
