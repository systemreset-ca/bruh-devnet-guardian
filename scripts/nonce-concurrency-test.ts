/**
 * REAL multi-session concurrency test for the durable nonce store.
 *
 * Each attempt is a separate HTTP request to the database routine, so attempts
 * land on distinct database sessions/connections — unlike the single-session
 * SQL suite. For every trial, N simultaneous requests race for the same
 * (key_id, nonce); exactly one must report first use.
 *
 * Prints booleans and counts only. No key material, no request bodies, no
 * error bodies are logged.
 */
const url = process.env["SUPABASE_URL"];
const serviceKey = process.env["SUPABASE_SERVICE_ROLE_KEY"];

if (!url || !serviceKey) {
  console.error("FAIL  backend credentials not available in this environment");
  process.exit(1);
}

const TRIALS = 8;
const RACERS = 6;

async function consume(keyId: string, nonce: string): Promise<boolean> {
  const response = await fetch(`${url}/rest/v1/rpc/consume_signer_nonce`, {
    method: "POST",
    headers: {
      // Opaque sb_secret_* keys are not JWTs: send apikey only, never Bearer.
      apikey: serviceKey!,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ p_key_id: keyId, p_nonce: nonce, p_ttl_seconds: 60 }),
  });
  if (!response.ok) throw new Error(`rpc_failed_status_${response.status}`);
  const value = await response.json();
  if (typeof value !== "boolean") throw new Error("rpc_non_boolean");
  return value;
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `nonce_${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

let passed = 0;
let failed = 0;

function record(name: string, ok: boolean, note = ""): void {
  if (ok) passed += 1;
  else failed += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${note ? `  (${note})` : ""}`);
}

const keyId = "signer-key-cnc";

for (let trial = 1; trial <= TRIALS; trial += 1) {
  const nonce = randomNonce();
  const results = await Promise.all(
    Array.from({ length: RACERS }, () => consume(keyId, nonce)),
  );
  const winners = results.filter(Boolean).length;
  record(
    `multi_session_race_trial_${trial}_exactly_one_winner`,
    winners === 1,
    `${RACERS} simultaneous sessions, winners=${winners}`,
  );
}

// Distinct nonces must all succeed (no false replay rejections under load).
const distinct = Array.from({ length: RACERS }, () => randomNonce());
const distinctResults = await Promise.all(distinct.map((n) => consume(keyId, n)));
record(
  "multi_session_distinct_nonces_all_first_use",
  distinctResults.every(Boolean),
  `${RACERS} simultaneous sessions`,
);

// TTL bounds are enforced server-side even for a direct routine caller.
for (const ttl of [0, -1, 3600]) {
  let rejected = false;
  try {
    await fetch(`${url}/rest/v1/rpc/consume_signer_nonce`, {
      method: "POST",
      headers: {
        apikey: serviceKey!,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_key_id: keyId, p_nonce: randomNonce(), p_ttl_seconds: ttl }),
    }).then((r) => {
      if (!r.ok) rejected = true;
    });
  } catch {
    rejected = true;
  }
  record(`multi_session_ttl_${ttl}_rejected`, rejected);
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
