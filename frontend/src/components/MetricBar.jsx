export default function MetricBar({ label, value, suffix = "%", max = 100 }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs text-slate-300">
        <span>{label}</span>
        <span className="text-slate-200 font-semibold">
          {value.toFixed(1)}
          {suffix}
        </span>
      </div>
      <div className="h-2 rounded-full bg-white/5 ring-1 ring-white/10 overflow-hidden">
        <div className="h-full w-[--w] bg-sky-400/90" style={{ "--w": `${pct}%` }} />
      </div>
    </div>
  );
}
