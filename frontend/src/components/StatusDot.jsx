export default function StatusDot({ tone = "ok" }) {
  const cls =
    tone === "ok"
      ? "bg-emerald-400"
      : tone === "warn"
      ? "bg-yellow-400"
      : tone === "err"
      ? "bg-red-500"
      : "bg-slate-400";

  return <span className={`inline-block h-2.5 w-2.5 rounded-full ${cls}`} />;
}
