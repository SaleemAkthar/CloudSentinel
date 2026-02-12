export default function AlertSummaryCard({
  title,
  count,
  color,
  icon
}) {
  const colors = {
    red: "border-red-500 text-red-400",
    orange: "border-orange-400 text-orange-300",
    yellow: "border-yellow-400 text-yellow-300",
    blue: "border-blue-400 text-blue-300",
  };

  return (
    <div
      className={`rounded-xl border p-5 bg-white/5 ${colors[color]}`}
    >
      <div className="flex justify-between items-center">
        <div>
          <div className="text-sm text-slate-400">
            {title}
          </div>
          <div className="text-3xl font-bold mt-2">
            {count}
          </div>
        </div>

        <div className="text-3xl opacity-70">
          {icon}
        </div>
      </div>
    </div>
  );

  
}
