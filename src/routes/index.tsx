import { createFileRoute } from "@tanstack/react-router";
import { StatusBadge } from "@/components/StatusBadge";

const TITLE = "BRUH Devnet Signer — Operator Status";
const DESCRIPTION =
  "Operator status console for the BRUH devnet signer. Devnet only: no funding, no mainnet, no signing endpoints, no keys.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESCRIPTION },
      { name: "robots", content: "noindex, nofollow" },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESCRIPTION },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: OperatorStatus,
});

const capabilities: { name: string; tone: "ok" | "warn"; state: string; note: string }[] = [
  {
    name: "Solana web3.js 1.98.4 (server-side)",
    tone: "warn",
    state: "supported*",
    note: "Pure-JS and fetch-based; must be pinned to the exact version. Native/node-gyp add-ons are not usable.",
  },
  {
    name: "AES-256-GCM envelope encryption",
    tone: "ok",
    state: "verified",
    note: "32-byte key, 12-byte IV, 16-byte auth tag round-trip confirmed on the runtime.",
  },
  {
    name: "Secure secret generation & storage",
    tone: "ok",
    state: "available",
    note: "Managed encrypted store; values exposed only as server-side variables read inside handlers.",
  },
  {
    name: "Server-only HTTP routes",
    tone: "ok",
    state: "available",
    note: "Server-side handlers and typed server calls; no secret material reaches the browser bundle.",
  },
  {
    name: "Runtime baseline",
    tone: "ok",
    state: "node 22 / worker",
    note: "No subprocesses and no real OS filesystem in production — factored into later key handling.",
  },
];

const posture: { name: string; value: string }[] = [
  { name: "Wallet funding", value: "disabled" },
  { name: "Mainnet", value: "disabled" },
  { name: "Signing endpoints", value: "not deployed" },
  { name: "Imported keys", value: "none" },
  { name: "Production secrets", value: "none generated" },
  { name: "External secret scopes", value: "not linked" },
];

const evidence: { name: string; tone: "ok" | "warn"; state: string; note: string }[] = [
  {
    name: "Local test-run proof (CLI)",
    tone: "ok",
    state: "verified",
    note: "Envelope, transfer-signing, request-auth, one-time-token and third-party sign-in suites run in the local test runner only. This is not evidence about the deployed runtime.",
  },
  {
    name: "Deployed runtime proof (Worker)",
    tone: "ok",
    state: "verified: offline only",
    note: "An authenticated diagnostic request executed on the deployed runtime and returned booleans only: envelope, scope-binding, tamper rejection and offline transfer signing all held. Unauthenticated and replayed requests were denied there. This covers offline work only.",
  },
  {
    name: "Network / on-chain reads",
    tone: "warn",
    state: "request-only reader ready for a live read-only check; not yet proven on the deployed runtime",
    note: "A reviewed request-only devnet reader now exists and never creates the wallet SDK connection object that this runtime cannot build. It checks the network fingerprint, takes a settled block reference and confirms the network charge stays inside the reserved allowance. One real read-only check passed in a local test environment; a live read-only check is prepared and awaiting review and publish, so nothing has been proven on the deployed runtime yet, nothing is wired to wallets or the chat bot, and no send or broadcast path is reachable. No value may be substituted from stored records.",
  },

  {
    name: "Diagnostic probe",
    tone: "ok",
    state: "disabled (live confirmed)",
    note: "The switch is off in source and in the published deployment: an independent live request to the diagnostic address returned 404 with no-store. No caller credential was ever exposed.",
  },
  {
    name: "Third-party sign-in proof",
    tone: "warn",
    state: "fixtures only",
    note: "Accepted cases used locally generated test keys. No real live sign-in payload or real account has been verified.",
  },
  {
    name: "Wallet provisioning",
    tone: "warn",
    state: "source only; not applied",
    note: "Provisioning logic and its storage proposal exist with tests, but nothing is applied, enabled or funded. Approval and wrapping-key sources are absent, so every request is refused. Accepted test cases used mock approvals, not real group membership proof.",
  },

];

function OperatorStatus() {
  return (
    <main className="mx-auto min-h-screen w-full max-w-3xl px-5 py-14">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="label-key">Operator console</p>
          <h1 className="console mt-2 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            BRUH Devnet Signer
          </h1>
          <p className="console mt-2 text-sm text-muted-foreground">
            env: devnet · phase: 0 · scope: isolated
          </p>
        </div>
        <StatusBadge tone="warn">armed: no</StatusBadge>
      </header>

      <p className="mt-8 max-w-prose text-sm leading-relaxed text-muted-foreground">
        This page is intentionally inert. It reports runtime compatibility and operating posture
        only, and never displays addresses, balances, key material, secret names, or endpoints.
      </p>

      <section className="panel mt-10 p-5" aria-labelledby="capabilities">
        <h2 id="capabilities" className="label-key">
          Runtime capability matrix
        </h2>
        <ul className="mt-4 divide-y divide-border">
          {capabilities.map((c) => (
            <li key={c.name} className="py-3 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="console text-sm text-foreground">{c.name}</span>
                <StatusBadge tone={c.tone}>{c.state}</StatusBadge>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{c.note}</p>
            </li>
          ))}
        </ul>
        <p className="console mt-4 text-[0.6875rem] text-muted-foreground">
          * supported with a version-pinning constraint.
        </p>
      </section>

      <section className="panel mt-6 p-5" aria-labelledby="posture">
        <h2 id="posture" className="label-key">
          Safety posture
        </h2>
        <dl className="mt-4 grid gap-x-6 gap-y-3 sm:grid-cols-2">
          {posture.map((p) => (
            <div
              key={p.name}
              className="flex items-center justify-between gap-3 border-b border-border pb-2"
            >
              <dt className="console text-xs text-muted-foreground">{p.name}</dt>
              <dd>
                <StatusBadge tone="locked">{p.value}</StatusBadge>
              </dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="panel mt-6 p-5" aria-labelledby="evidence">
        <h2 id="evidence" className="label-key">
          Verification evidence
        </h2>
        <ul className="mt-4 divide-y divide-border">
          {evidence.map((e) => (
            <li key={e.name} className="py-3 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="console text-sm text-foreground">{e.name}</span>
                <StatusBadge tone={e.tone}>{e.state}</StatusBadge>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{e.note}</p>
            </li>
          ))}
        </ul>
        <p className="console mt-4 text-[0.6875rem] text-muted-foreground">
          Local test-run proof and deployed-runtime proof are reported separately and never merged.
        </p>
      </section>

      <section className="panel mt-6 p-5" aria-labelledby="reference">
        <h2 id="reference" className="label-key">
          Reviewed source reference
        </h2>
        <p className="console mt-3 text-xs leading-relaxed text-muted-foreground">
          systemreset-ca/bruhlegends · draft PR 46 · branch codex/devnet-custody-core
        </p>
        <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
          Read-only reference. That repository is never modified from here, and no credentials from
          any other project are reused.
        </p>
      </section>

      <footer className="console mt-10 text-[0.6875rem] tracking-widest uppercase text-muted-foreground">
        no secrets · no wallets · devnet only
      </footer>
    </main>
  );
}
