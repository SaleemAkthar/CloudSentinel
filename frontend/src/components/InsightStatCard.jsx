export default function InsightStatCard({
  title,
  value,
  subtext,
  color
}) {
  const colors = {
    green: "text-emerald-400 border-emerald-400/40",
    blue: "text-blue-400 border-blue-400/40",
    yellow: "text-yellow-400 border-yellow-400/40",
    purple: "text-purple-400 border-purple-400/40",
  };

  return (
    <div className={`rounded-xl p-5 bg-white/5 border ${colors[color]}`}>
      <div className="text-sm text-slate-400">
        {title}
      </div>

      <div className="text-3xl font-bold mt-2 text-white">
        {value}
      </div>

      <div className="text-xs mt-1 text-slate-400">
        {subtext}
      </div>
    </div>
  );
}
