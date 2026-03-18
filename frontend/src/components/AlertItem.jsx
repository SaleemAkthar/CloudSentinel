export default function AlertItem({ alert, onInvestigate }) {
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

  const decisionStyles = {
    BLOCK: "bg-red-500/15 text-red-400 border-red-500/40",
    INVESTIGATE: "bg-orange-500/15 text-orange-400 border-orange-500/40",
    MONITOR: "bg-yellow-500/15 text-yellow-400 border-yellow-500/40",
    PASS: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
  };

  const features = alert.features || {};
  const timeAgo = alert.timestamp
    ? new Date(alert.timestamp).toLocaleString()
    : "N/A";
  const colorClass = severityColors[alert.severity] || severityColors.INFO;

  // ── Layer 2 Scanner data ────────────────────────────────────────────
  const l2 = alert.layer2_report || null;
  const patterns = l2?.patterns?.matched_patterns || [];
  const topThreat = l2?.patterns?.top_threat || null;
  const riskScore = l2?.risk?.adjusted_score;
  const decision = l2?.decision || alert.threat_type || null;
  const scanTime = l2?.elapsed_ms;
  const ipCountry = l2?.ip?.geo?.country_name;
  const ipReputation = l2?.ip?.reputation?.label;
  const confidence = alert.confidence ?? l2?.risk?.confidence;

  return (
    <div className={`p-5 border-l-4 flex justify-between items-start gap-4 min-h-24 ${colorClass}`}>
      {/* LEFT CONTENT */}
      <div className="flex-1 min-w-0">
        {/* Row 1: Function name + badges */}
        <div className="flex items-center gap-2 flex-wrap mb-2">
          <h3 className="text-lg font-semibold text-white truncate">
            {alert.function || "Unknown Alert"}
          </h3>

          <span
            className={`px-3 py-1 text-xs font-semibold rounded-full ${
              badgeStyles[alert.severity]
            }`}
          >
            {alert.severity}
          </span>

          <span
            className={`text-xs font-semibold whitespace-nowrap ${
              statusColors[alert.status] || "text-slate-400"
            }`}
          >
            {alert.status || "N/A"}
          </span>

          {/* L2 Decision badge */}
          {decision && (
            <span
              className={`px-2 py-0.5 text-xs font-semibold rounded-full border ${
                decisionStyles[decision] || "bg-slate-500/15 text-slate-400 border-slate-500/40"
              }`}
            >
              {decision}
            </span>
          )}
        </div>

        {/* Row 2: Core metrics */}
        <p className="text-slate-300 text-sm mb-1 break-words">
          Anomaly Score:{" "}
          <span className="font-semibold">
            {((alert.anomaly_score || 0) * 100).toFixed(1)}%
          </span>
          {" "}• Duration:{" "}
          <span className="font-semibold">{features.duration_ms || 0}ms</span>
          {" "}• Calls:{" "}
          <span className="font-semibold">{features.outbound_calls || 0}</span>
          {confidence != null && (
            <>
              {" "}• Confidence:{" "}
              <span className="font-semibold">
                {(confidence * 100).toFixed(0)}%
              </span>
            </>
          )}
        </p>

        {/* Row 3: L2 attack patterns (only if Layer 2 data exists) */}
        {patterns.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-1.5">
            {patterns.map((p, idx) => (
              <span
                key={idx}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-white/5 border border-white/10 text-slate-300"
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    p.confidence >= 0.7
                      ? "bg-red-400"
                      : p.confidence >= 0.4
                      ? "bg-orange-400"
                      : "bg-yellow-400"
                  }`}
                />
                {p.name || p.attack_type}
                <span className="text-slate-500 ml-0.5">
                  {(p.confidence * 100).toFixed(0)}%
                </span>
              </span>
            ))}
          </div>
        )}

        {/* Row 4: Footer details */}
        <div className="text-xs text-slate-400 flex flex-wrap gap-x-2">
          <span>
            Destinations: {features.unique_destinations || 0} | Errors:{" "}
            {features.error_count || 0}
          </span>

          {ipCountry && (
            <span>
              | IP: {features.ip_address || "?"}{" "}
              <span className="text-slate-500">({ipCountry})</span>
            </span>
          )}

          {ipReputation && ipReputation !== "CLEAN" && (
            <span
              className={
                ipReputation === "MALICIOUS"
                  ? "text-red-400"
                  : "text-orange-400"
              }
            >
              | Rep: {ipReputation}
            </span>
          )}

          {riskScore != null && (
            <span>| Risk: {(riskScore * 100).toFixed(0)}%</span>
          )}

          {scanTime != null && (
            <span className="text-slate-500">| L2 Scan: {scanTime}ms</span>
          )}

          <span>| {timeAgo}</span>
        </div>
      </div>

      {/* RIGHT ACTION BUTTONS */}
      <div className="flex gap-2 flex-shrink-0">
        <button
          onClick={() => onInvestigate?.(alert.id)}
          className="px-3 py-2 text-xs rounded-lg bg-blue-600/20 border border-blue-500 text-blue-300 hover:bg-blue-600/30 whitespace-nowrap"
        >
          Investigate
        </button>

        <button className="px-3 py-2 text-xs rounded-lg bg-red-600/20 border border-red-500 text-red-400 hover:bg-red-600/30 whitespace-nowrap">
          Block
        </button>
      </div>
    </div>
  );
}