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
  __resetNonceStore,
  bodyDigestHex,
  canonicalString,
  newNonce,
  signCanonical,
  verifySignerRequest,
} from "../src/lib/custody/request-auth.server";

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
  __resetNonceStore();
  const secret = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("hex");
  const path = "/api/public/signer/selftest";
  const body = JSON.stringify({ probe: true });

  const sign = (opts?: { ts?: string; nonce?: string; body?: string; secret?: string }) => {
    const ts = opts?.ts ?? String(Date.now());
    const nonce = opts?.nonce ?? newNonce();
    const payload = opts?.body ?? body;
    const signature = signCanonical(
      opts?.secret ?? secret,
      canonicalString({
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
        [HEADER_KEY_ID]: "selftest",
      }),
      rawBody: payload,
    };
  };
  const verify = (
    req: { headers: Headers; rawBody: string },
    secretOverride?: string | undefined,
  ) =>
    verifySignerRequest({
      method: "POST",
      path,
      headers: req.headers,
      rawBody: req.rawBody,
      secret: secretOverride === undefined ? secret : secretOverride,
    });

  const good = sign();
  check("valid signed request accepted", verify(good).ok);
  const replay = verify(good);
  check("replayed nonce rejected", !replay.ok && replay.reason === "replayed_nonce");

  const noSecret = verifySignerRequest({
    method: "POST",
    path,
    headers: sign().headers,
    rawBody: body,
    secret: undefined,
  });
  check("missing caller secret rejects", !noSecret.ok && noSecret.reason === "secret_unavailable");

  const shortSecret = verifySignerRequest({
    method: "POST",
    path,
    headers: sign().headers,
    rawBody: body,
    secret: "tooshort",
  });
  check("short secret rejects", !shortSecret.ok && shortSecret.reason === "secret_unavailable");

  const tamperedBody = sign();
  const withOtherBody = { ...tamperedBody, rawBody: JSON.stringify({ probe: false }) };
  const digestFail = verify(withOtherBody);
  check("body digest binding rejects altered body", !digestFail.ok);

  const stale = verify(sign({ ts: String(Date.now() - 5 * 60_000) }));
  check("stale timestamp rejected", !stale.ok && stale.reason === "stale_timestamp");

  const future = verify(sign({ ts: String(Date.now() + 5 * 60_000) }));
  check("far-future timestamp rejected", !future.ok && future.reason === "stale_timestamp");

  const wrongKey = verify(
    sign({
      secret: Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("hex"),
    }),
  );
  check("wrong caller secret rejected", !wrongKey.ok && wrongKey.reason === "bad_signature");

  const wrongPath = verifySignerRequest({
    method: "POST",
    path: "/api/public/signer/other",
    headers: sign().headers,
    rawBody: body,
    secret,
  });
  check("path binding enforced", !wrongPath.ok && wrongPath.reason === "bad_signature");

  const wrongMethod = verifySignerRequest({
    method: "GET",
    path,
    headers: sign().headers,
    rawBody: body,
    secret,
  });
  check("method binding enforced", !wrongMethod.ok && wrongMethod.reason === "bad_signature");

  const missingHeaders = verifySignerRequest({
    method: "POST",
    path,
    headers: new Headers(),
    rawBody: body,
    secret,
  });
  check(
    "missing auth headers rejected",
    !missingHeaders.ok && missingHeaders.reason === "malformed_request",
  );

  const oversized = verifySignerRequest({
    method: "POST",
    path,
    headers: sign().headers,
    rawBody: "x".repeat(64 * 1024 + 1),
    secret,
  });
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
