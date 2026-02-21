export default function AlertItem({ alert }) {
  if (!alert) return null;

  const severityColors = {
    CRITICAL: "border-l-4 border-red-500 border-red-500/40",
    WARNING: "border-l-4 border-orange-400 border-orange-400/40",
    INFO: "border-l-4 border-yellow-400 border-yellow-400/40",
  };

  const badgeStyles = {
  CRITICAL: "bg-red-500/15 text-red-400 border border-red-500/40",
  WARNING: "bg-orange-500/15 text-orange-400 border border-orange-500/40",
  INFO: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/40",
  };

  const statusColors = {
    OPEN: "text-red-400",
    CLOSED: "text-emerald-400",
  };

  const features = alert.features || {};
  const timeAgo = alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "N/A";
  const colorClass = severityColors[alert.severity] || severityColors.INFO;

  return (
    <div className={`p-5 border-l-4 flex justify-between items-start gap-4 min-h-24 ${colorClass}`}>
      {/* LEFT CONTENT */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-2">
          <h3 className="text-lg font-semibold text-white truncate">
            {alert.function || "Unknown Alert"}
          </h3>

          <span   className={`px-3 py-1 text-xs font-semibold rounded-full ${
                badgeStyles[alert.severity]
              }`}>
                {alert.severity}
          </span>

          <span className={`text-xs font-semibold whitespace-nowrap ${statusColors[alert.status] || "text-slate-400"}`}>
            {alert.status || "N/A"}
          </span>
        </div>

        <p className="text-slate-300 text-sm mb-2 break-words">
          Anomaly Score: <span className="font-semibold">{((alert.anomaly_score || 0) * 100).toFixed(1)}%</span> 
          • Duration: <span className="font-semibold">{features.duration_ms || 0}ms</span>
          • Calls: <span className="font-semibold">{features.outbound_calls || 0}</span>
        </p>

        <div className="text-xs text-slate-400">
          Destinations: {features.unique_destinations || 0} | 
          Errors: {features.error_count || 0} | 
          {timeAgo}
        </div>
      </div>

      {/* RIGHT ACTION BUTTONS */}
      <div className="flex gap-2 flex-shrink-0">
        <button className="px-3 py-2 text-xs rounded-lg bg-blue-600/20 border border-blue-500 text-blue-300 hover:bg-blue-600/30 whitespace-nowrap">
          Investigate
        </button>

        <button className="px-3 py-2 text-xs rounded-lg bg-red-600/20 border border-red-500 text-red-400 hover:bg-red-600/30 whitespace-nowrap">
          Block
        </button>
      </div>
    </div>
  );
}
