/**
 * CLI self-check for third-party Telegram Mini App initData verification.
 *
 * FIXTURE SCOPE — READ THIS BEFORE INTERPRETING RESULTS:
 *   Every "accepted" case below is signed with a GENERIC, LOCALLY GENERATED
 *   Ed25519 test key, verified against that same generated key. This proves the
 *   canonical-string construction, parsing, binding and rejection logic only.
 *   It is NOT proof that any real Telegram account or real Telegram signature
 *   was verified: no valid live initData is available yet, so nothing here
 *   exercises Telegram's production key against a genuine payload.
 *   The pinned production key and bot ID are only asserted as constants, and
 *   generated-key fixtures are confirmed to FAIL against the production key.
 *
 * Output is booleans and non-secret metadata only.
 */
import { ed25519 } from "@noble/curves/ed25519.js";

import {
  EXPECTED_BOT_ID,
  TELEGRAM_PRODUCTION_ED25519_PUBLIC_KEY_HEX,
  PINNED_INIT_DATA_CONFIG,
  MAX_INIT_DATA_BYTES,
  verifyThirdPartyInitData,
  verifyThirdPartyInitDataWithConfig,
  type InitDataVerifierConfig,
} from "../src/lib/telegram/init-data.server";

let passed = 0;
let failed = 0;

function check(name: string, ok: boolean): void {
  if (ok) passed += 1;
  else failed += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

// --- generic generated test key (NOT Telegram's) ---
const testSecretKey = ed25519.keygen().secretKey;
const testPublicKey = ed25519.getPublicKey(testSecretKey);
const testConfig: InitDataVerifierConfig = {
  botId: EXPECTED_BOT_ID,
  publicKeyHex: toHex(testPublicKey),
};

const nowMs = Date.now();
const authDate = Math.floor(nowMs / 1000);

function buildInitData(opts?: {
  botId?: string;
  authDate?: number;
  userId?: number | string;
  extra?: Array<[string, string]>;
  omitSignature?: boolean;
  signature?: string;
  secretKey?: Uint8Array;
  duplicateKey?: string;
}): string {
  const fields: Array<[string, string]> = [
    ["auth_date", String(opts?.authDate ?? authDate)],
    ["query_id", "AAF_test_query_id"],
    ["user", JSON.stringify({ id: opts?.userId ?? 424242, first_name: "Fixture" })],
    ...(opts?.extra ?? []),
  ];

  const canonical = [...fields]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
  const message = `${opts?.botId ?? EXPECTED_BOT_ID}:WebAppData\n${canonical}`;
  const signature =
    opts?.signature ??
    toBase64Url(
      ed25519.sign(new TextEncoder().encode(message), opts?.secretKey ?? testSecretKey),
    );

  const parts = fields.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  if (!opts?.omitSignature) parts.push(`signature=${signature}`);
  if (opts?.duplicateKey) {
    const dup = fields.find(([k]) => k === opts.duplicateKey);
    if (dup) parts.push(`${encodeURIComponent(dup[0])}=${encodeURIComponent(dup[1])}`);
  }
  return parts.join("&");
}

console.log("--- pinned server config (constants only, no live proof) ---");
check(
  "production public key pinned exactly",
  TELEGRAM_PRODUCTION_ED25519_PUBLIC_KEY_HEX ===
    "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d",
);
check("expected bot ID pinned exactly", EXPECTED_BOT_ID === "8763268934");
check(
  "pinned config uses the production key and expected bot ID",
  PINNED_INIT_DATA_CONFIG.botId === EXPECTED_BOT_ID &&
    PINNED_INIT_DATA_CONFIG.publicKeyHex === TELEGRAM_PRODUCTION_ED25519_PUBLIC_KEY_HEX,
);

console.log("\n--- generated-key fixtures (logic proof only) ---");
const valid = buildInitData();
const accepted = verifyThirdPartyInitDataWithConfig(valid, testConfig, { nowMs });
check(
  "fixture signed with generated key accepted under that same generated key",
  accepted.ok && accepted.telegramUserId === "424242" && accepted.botId === EXPECTED_BOT_ID,
);
check(
  "extra unknown signed field still verifies (all received fields are signed)",
  verifyThirdPartyInitDataWithConfig(
    buildInitData({ extra: [["chat_type", "private"]] }),
    testConfig,
    { nowMs },
  ).ok,
);

console.log("\n--- generated-key fixtures rejected by the production key ---");
const productionCheck = verifyThirdPartyInitData(valid, { nowMs });
check(
  "generated-key fixture REJECTED against Telegram production key",
  !productionCheck.ok && productionCheck.reason === "bad_signature",
);

console.log("\n--- tampering, binding and format rejections ---");
function reject(name: string, raw: string, reason: string, config = testConfig): void {
  const result = verifyThirdPartyInitDataWithConfig(raw, config, { nowMs });
  check(`${name} (${reason})`, !result.ok && result.reason === reason);
}

// tampering: change a signed value after signing
reject(
  "tampered user id rejected",
  valid.replace(/user=[^&]*/, () =>
    `user=${encodeURIComponent(JSON.stringify({ id: 999999, first_name: "Fixture" }))}`,
  ),
  "bad_signature",
);
reject(
  "tampered auth_date rejected",
  valid.replace(/auth_date=\d+/, `auth_date=${authDate - 5}`),
  "bad_signature",
);
reject(
  "appended unsigned field rejected",
  `${valid}&injected=1`,
  "bad_signature",
);

// wrong bot binding: same key, different bot ID in the canonical string
reject(
  "wrong bot binding rejected (payload signed for another bot ID)",
  buildInitData({ botId: "1111111111" }),
  "bad_signature",
);
check(
  "verifier bot ID cannot be overridden by the payload",
  !verifyThirdPartyInitDataWithConfig(valid, { ...testConfig, botId: "1111111111" }, { nowMs })
    .ok,
);

// wrong key
const otherSecret = ed25519.keygen().secretKey;
reject(
  "wrong signing key rejected",
  buildInitData({ secretKey: otherSecret }),
  "bad_signature",
);

// signature format
reject("missing signature rejected", buildInitData({ omitSignature: true }), "missing_signature");
reject(
  "signature with wrong length rejected",
  buildInitData({ signature: toBase64Url(new Uint8Array(32)) }),
  "malformed_signature",
);
reject(
  "signature with non-base64url characters rejected",
  buildInitData({ signature: "not*base64url*value" }),
  "malformed_signature",
);

// duplicate parameters
reject("duplicate auth_date parameter rejected", buildInitData({ duplicateKey: "auth_date" }), "duplicate_parameter");
reject("duplicate user parameter rejected", buildInitData({ duplicateKey: "user" }), "duplicate_parameter");

// age
reject(
  "stale payload rejected",
  buildInitData({ authDate: authDate - 601 }),
  "stale_payload",
);
reject(
  "future payload rejected",
  buildInitData({ authDate: authDate + 600 }),
  "future_payload",
);
check(
  "payload just inside the freshness window accepted",
  verifyThirdPartyInitDataWithConfig(buildInitData({ authDate: authDate - 299 }), testConfig, {
    nowMs,
  }).ok,
);

// auth_date / user format
reject(
  "non-numeric auth_date rejected",
  valid.replace(/auth_date=\d+/, "auth_date=not-a-number"),
  "malformed_auth_date",
);
reject(
  "non-numeric user id rejected",
  buildInitData({ userId: "424242" }),
  "malformed_user",
);
reject(
  "user payload that is not valid JSON rejected",
  valid.replace(/user=[^&]*/, "user=%7Bbroken"),
  "malformed_user",
);

// structural
reject("empty payload rejected", "", "empty_payload");
reject("payload without key=value pairs rejected", "garbage-with-no-pairs", "malformed_payload");
reject(
  "oversized payload rejected",
  `${valid}&pad=${"a".repeat(MAX_INIT_DATA_BYTES)}`,
  "payload_too_large",
);
check(
  "invalid pinned key length rejects as config failure",
  (() => {
    const r = verifyThirdPartyInitDataWithConfig(valid, { botId: EXPECTED_BOT_ID, publicKeyHex: "abcd" }, { nowMs });
    return !r.ok && r.reason === "config_unavailable";
  })(),
);

console.log(`\n${passed} passed, ${failed} failed`);
console.log(
  "NOTE: accepted cases used generic generated keys only. No real Telegram signature " +
    "or real Telegram account has been verified in this slice.",
);
if (failed > 0) process.exit(1);
