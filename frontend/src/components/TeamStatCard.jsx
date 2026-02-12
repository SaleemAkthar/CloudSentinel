export default function TeamStatCard({ title, value, highlight }) {
  return (
    <div
      className={`rounded-xl p-5 border ${
        highlight
          ? "border-emerald-400 bg-emerald-500/10"
          : "border-white/10 bg-white/5"
      }`}
    >
      <div className="text-sm text-slate-400">
        {title}
      </div>

      <div className="flex items-center justify-between mt-2">
        <div className="text-3xl font-bold text-white">
          {value}
        </div>

        {highlight && (
          <div className="w-3 h-3 rounded-full bg-emerald-400"></div>
        )}
      </div>
    </div>
  );
}
