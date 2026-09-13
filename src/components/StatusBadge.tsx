type Tone = "ok" | "warn" | "locked";

const toneClass: Record<Tone, string> = {
  ok: "border-ok/40 bg-ok/10 text-ok",
  warn: "border-warn/40 bg-warn/10 text-warn",
  locked: "border-border bg-secondary text-locked",
};

export function StatusBadge({ tone, children }: { tone: Tone; children: string }) {
  return (
    <span
      className={`console inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-[0.6875rem] tracking-widest uppercase ${toneClass[tone]}`}
    >
      <span className="size-1.5 rounded-full bg-current" aria-hidden="true" />
      {children}
    </span>
  );
}
