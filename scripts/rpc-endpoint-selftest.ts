/**
 * Server-only devnet RPC configuration tests.
 *
 * No secret value is printed. All keys here are throwaway literals invented for
 * the test; none is a real provider key. Nothing hits the network.
 */
import {
  HELIUS_DEVNET_HOST,
  describeDevnetRpcConfig,
  resolveDevnetRpcEndpoint,
} from "../src/lib/custody/rpc-endpoint.server";

let passed = 0;
let failed = 0;
const check = (name: string, ok: boolean) => {
  if (ok) passed += 1;
  else {
    failed += 1;
    console.log(`FAIL ${name}`);
  }
};
const rejects = (fn: () => unknown) => {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
};

const KEY = "throwaway-devnet-key-0001";

// ---------------------------------------------------------------- construction
{
  const endpoint = resolveDevnetRpcEndpoint({ devnetApiKey: KEY });
  const url = new URL(endpoint);
  check("endpoint is https", url.protocol === "https:");
  check("endpoint host is devnet helius", url.hostname === HELIUS_DEVNET_HOST);
  check("endpoint carries no userinfo or fragment", !url.username && !url.password && !url.hash);
  check("endpoint carries the api key parameter", url.searchParams.get("api-key") === KEY);
  check("endpoint has no other parameters", [...url.searchParams.keys()].length === 1);
  check("whitespace around the key is trimmed", resolveDevnetRpcEndpoint({ devnetApiKey: ` ${KEY} ` }) === endpoint);
}

// ------------------------------------------------------------- fails closed
check("missing key fails closed", rejects(() => resolveDevnetRpcEndpoint({})));
check("empty key fails closed", rejects(() => resolveDevnetRpcEndpoint({ devnetApiKey: "   " })));
check("short key fails closed", rejects(() => resolveDevnetRpcEndpoint({ devnetApiKey: "abc" })));
check(
  "key with illegal characters fails closed",
  rejects(() => resolveDevnetRpcEndpoint({ devnetApiKey: "bad key with spaces" })),
);

// -------------------------------------------------- explicit override policy
const override = (rpcUrl: string) => resolveDevnetRpcEndpoint({ devnetApiKey: KEY, rpcUrl });
check(
  "valid devnet override is used verbatim",
  override(`https://${HELIUS_DEVNET_HOST}/?api-key=${KEY}`) === `https://${HELIUS_DEVNET_HOST}/?api-key=${KEY}`,
);
check("mainnet helius host rejected", rejects(() => override(`https://mainnet.helius-rpc.com/?api-key=${KEY}`)));
check("public solana rpc rejected", rejects(() => override("https://api.devnet.solana.com")));
check("plain http rejected", rejects(() => override(`http://${HELIUS_DEVNET_HOST}/`)));
check("websocket scheme rejected", rejects(() => override(`wss://${HELIUS_DEVNET_HOST}/`)));
check("userinfo rejected", rejects(() => override(`https://user:pass@${HELIUS_DEVNET_HOST}/`)));
check("fragment rejected", rejects(() => override(`https://${HELIUS_DEVNET_HOST}/#x`)));
check("look-alike suffix host rejected", rejects(() => override("https://devnet.helius-rpc.com.evil.example/")));
check("garbage url rejected", rejects(() => override("not a url")));
check(
  "invalid override never silently falls back to the constructed endpoint",
  rejects(() => override("https://api.mainnet-beta.solana.com")),
);

// -------------------------------------------------------------- boolean report
{
  const report = describeDevnetRpcConfig({ devnetApiKey: KEY });
  check("report is booleans only", Object.values(report).every((v) => typeof v === "boolean"));
  const serialized = JSON.stringify(report);
  check("report contains no key material", !serialized.includes(KEY));
  check("report contains no host or url", !serialized.includes("helius") && !serialized.includes("https"));
  check(
    "report marks the key present and the endpoint resolvable",
    report.devnetApiKeyPresent && report.devnetApiKeyWellFormed && report.endpointResolved,
  );
  check(
    "report states no mainnet key and no public fallback",
    report.mainnetKeyUsed === false && report.publicRpcFallbackUsed === false,
  );
  check("report marks no explicit url", report.explicitRpcUrlPresent === false && report.explicitRpcUrlDevnetCompatible === false);
}
{
  const report = describeDevnetRpcConfig({ devnetApiKey: KEY, rpcUrl: `https://${HELIUS_DEVNET_HOST}/?api-key=${KEY}` });
  check("valid explicit url reported compatible", report.explicitRpcUrlPresent && report.explicitRpcUrlDevnetCompatible && report.endpointResolved);
}
{
  const report = describeDevnetRpcConfig({ devnetApiKey: KEY, rpcUrl: "https://mainnet.helius-rpc.com/" });
  check(
    "mainnet explicit url reported incompatible and unresolvable",
    report.explicitRpcUrlPresent && !report.explicitRpcUrlDevnetCompatible && !report.endpointResolved,
  );
}
{
  const report = describeDevnetRpcConfig({});
  check("absent key reported absent and unresolvable", !report.devnetApiKeyPresent && !report.endpointResolved);
}

// ------------------------------------------------ mainnet key is never read
{
  const source = await Bun.file("src/lib/custody/rpc-endpoint.server.ts").text();
  check("mainnet key name never appears in the config module", !source.includes("BRUH_MAINNET_API_KEY"));
  check("no public rpc endpoint literal in the config module", !source.includes("api.devnet.solana.com"));
}

console.log(`rpc-endpoint self-test: ${passed}/${passed + failed} passed`);
if (failed > 0) process.exit(1);
