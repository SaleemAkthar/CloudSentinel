export default function AlertItem({ alert }) {
  const severityColors = {
    critical: "text-red-400 border-red-500",
    high: "text-orange-400 border-orange-400",
    medium: "text-yellow-400 border-yellow-400",
  };

  const statusColors = {
    ACTIVE: "text-red-400",
    MITIGATING: "text-yellow-400",
    BLOCKED: "text-emerald-400",
    THROTTLED: "text-blue-400",
  };

  return (
    <div className="rounded-xl bg-white/5 border border-white/10 p-5">
      <div className="flex justify-between items-start">
        {/* LEFT CONTENT */}
        <div>
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold text-white">
              {alert.title}
            </h3>

            <span
              className={`text-xs px-2 py-1 rounded-full border ${severityColors[alert.severity]}`}
            >
              {alert.severity}
            </span>

            <span
              className={`text-xs font-semibold ${statusColors[alert.status]}`}
            >
              {alert.status}
            </span>
          </div>

          <p className="text-slate-400 mt-2 text-sm">
            {alert.description}
          </p>

          <div className="text-xs text-slate-500 mt-3">
            Target: {alert.target} &nbsp;&nbsp;
            Source: {alert.source} &nbsp;&nbsp;
            {alert.time}
          </div>
        </div>

        {/* RIGHT ACTION BUTTONS */}
        <div className="flex gap-3">
          <button className="px-4 py-2 text-sm rounded-lg bg-blue-600/20 border border-blue-500 text-blue-300 hover:bg-blue-600/30">
            Investigate
          </button>

          <button className="px-4 py-2 text-sm rounded-lg bg-red-600/20 border border-red-500 text-red-400 hover:bg-red-600/30">
            Block
          </button>
        </div>
      </div>
    </div>
  );
}
