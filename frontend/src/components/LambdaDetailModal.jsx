import { useState } from "react";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import ExpandLessRoundedIcon from "@mui/icons-material/ExpandLessRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import { useNavigate } from "react-router-dom";

// Severity colour map
const SEV = {
  CRITICAL: {
    bg: "bg-red-500/15",
    border: "border-red-500/40",
    text: "text-red-400",
    bar: "bg-red-500",
    dot: "bg-red-400",
  },
  WARNING: {
    bg: "bg-orange-500/15",
    border: "border-orange-500/40",
    text: "text-orange-400",
    bar: "bg-orange-400",
    dot: "bg-orange-400",
  },
  INFO: {
    bg: "bg-blue-500/15",
    border: "border-blue-500/40",
    text: "text-blue-400",
    bar: "bg-blue-400",
    dot: "bg-blue-400",
  },
};

const STATUS_COLORS = {
  active: {
    badge: "border-green-500 text-green-400 bg-green-500/15",
  },
  warning: {
    badge: "border-yellow-500 text-yellow-400 bg-yellow-500/15",
  },
  error: {
    badge: "border-red-500 text-red-400 bg-red-500/15",
  },
};

// Helpers
function formatTime(ts) {
  return new Date(ts).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function SeverityBar({ label, count, total }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  const style = SEV[label] || SEV.INFO;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className={`font-semibold ${style.text}`}>{label}</span>
        <span className="text-slate-400">
          {count} <span className="text-slate-500">({pct.toFixed(0)}%)</span>
        </span>
      </div>
      <div className="h-2 w-full rounded-full bg-white/5 ring-1 ring-white/10 overflow-hidden">
        <div
          className={`h-full rounded-full ${style.bar} transition-all duration-700 ease-out`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function AlertRow({ alert }) {
  const [open, setOpen] = useState(false);
  const sev = SEV[alert.severity] || SEV.INFO;
  const f = alert.features || {};

  return (
    <div className="border-b border-white/5 last:border-b-0">
      {/* Row Header */}
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.03] transition-colors group"
      >
        {/* Severity Dot */}
        <span className={`shrink-0 w-2 h-2 rounded-full ${sev.dot}`} />

        {/* ID */}
        <span className="text-xs font-mono text-slate-400 w-24 shrink-0 truncate">
          {alert.id}
        </span>

        {/* Function */}
        <span className="text-sm text-white font-medium flex-1 truncate">
          {alert.function}
        </span>

        {/* Severity Badge */}
        <span
          className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${sev.bg} ${sev.border} ${sev.text}`}
        >
          {alert.severity}
        </span>

        {/* Score */}
        <span className="text-xs text-slate-400 w-14 text-right shrink-0">
          {((alert.anomaly_score || 0) * 100).toFixed(0)}%
        </span>

        {/* Status */}
        <span
          className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
            alert.status === "OPEN"
              ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
              : "bg-slate-500/15 text-slate-400 border border-slate-500/30"
          }`}
        >
          {alert.status}
        </span>

        {/* Expand icon */}
        <span className="text-slate-500 group-hover:text-slate-300 transition-colors shrink-0">
          {open ? (
            <ExpandLessRoundedIcon fontSize="small" />
          ) : (
            <ExpandMoreRoundedIcon fontSize="small" />
          )}
        </span>
      </button>

      {/* Expanded Details */}
      {open && (
        <div className="px-4 pb-4 pt-1 ml-5 animate-[fadeSlideIn_0.2s_ease-out]">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 rounded-xl bg-white/[0.03] border border-white/5 p-4">
            {[
              { label: "Duration", value: `${f.duration_ms || 0}ms` },
              { label: "Outbound Calls", value: f.outbound_calls || 0 },
              { label: "Destinations", value: f.unique_destinations || 0 },
              { label: "Errors", value: f.error_count || 0 },
              {
                label: "Anomaly Score",
                value: `${((alert.anomaly_score || 0) * 100).toFixed(1)}%`,
              },
              { label: "Timestamp", value: formatTime(alert.timestamp) },
            ].map((item) => (
              <div key={item.label}>
                <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-0.5">
                  {item.label}
                </div>
                <div className="text-sm text-slate-200 font-medium">
                  {item.value}
                </div>
              </div>
            ))}
          </div>
          {alert.threat_type && (
            <div className="mt-2 text-xs text-slate-400">
              Threat Type:{" "}
              <span className="text-orange-300 font-medium">
                {alert.threat_type}
              </span>
            </div>
          )}
          {alert.features?.ip_address && (
            <div className="mt-1 text-xs text-slate-400">
              IP Address:{" "}
              <span className="text-slate-300 font-medium">
                {alert.features.ip_address}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ====================
// MAIN MODAL COMPONENT
// ====================
export default function LambdaDetailModal({
  fnName,
  fnStatus,
  fnStats,
  alerts,
  logs,
  onClose,
}) {
  const navigate = useNavigate();
  const total = alerts.length;

  const critCount = alerts.filter((a) => a.severity === "CRITICAL").length;
  const warnCount = alerts.filter((a) => a.severity === "WARNING").length;
  const infoCount = alerts.filter((a) => a.severity === "INFO").length;
  const openCount = alerts.filter((a) => a.status === "OPEN").length;

  const statusStyle = STATUS_COLORS[fnStatus] || STATUS_COLORS.active;

  return (
    <>
      {/* CSS keyframes */}
      <style>{`
        @keyframes modalBackdropIn { from { opacity: 0 } to { opacity: 1 } }
        @keyframes modalSlideUp {
          from { opacity: 0; transform: translateY(40px) scale(0.97) }
          to   { opacity: 1; transform: translateY(0) scale(1) }
        }
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-6px) }
          to   { opacity: 1; transform: translateY(0) }
        }
      `}</style>

      {/* Backdrop */}
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6"
        style={{ animation: "modalBackdropIn 0.25s ease-out forwards" }}
      >
        {/* Clickable backdrop */}
        <div
          className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          onClick={onClose}
        />

        {/* Modal Card */}
        <div
          className="relative z-10 w-full max-w-3xl max-h-[88vh] flex flex-col
                     rounded-2xl border border-white/10 bg-[#0b1530]/95
                     shadow-2xl shadow-black/40 overflow-hidden"
          style={{ animation: "modalSlideUp 0.3s ease-out forwards" }}
        >
          {/* ── Header ── */}
          <div className="shrink-0 border-b border-white/10 bg-[#0a1328]/90 backdrop-blur px-6 py-5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                {/* Title + Badge */}
                <div className="flex items-center gap-3 flex-wrap mb-2">
                  <h2 className="text-lg font-bold text-white truncate">
                    {fnName}
                  </h2>
                  <span
                    className={`text-xs px-2.5 py-1 rounded-full border font-semibold ${statusStyle.badge}`}
                  >
                    {fnStatus}
                  </span>
                </div>

                {/* Description */}
                <p className="text-sm text-slate-400 leading-relaxed">
                  Function activity from Layer 1 + Layer 2
                </p>

                {/* Meta Row */}
                {fnStats && (
                  <div className="flex items-center gap-4 mt-3 text-xs text-slate-500">
                    <span>
                      Invocations:{" "}
                      <span className="text-slate-300 font-medium">
                        {fnStats.invocations?.toLocaleString()}
                      </span>
                    </span>
                    <span>•</span>
                    <span>
                      Avg Duration:{" "}
                      <span className="text-slate-300 font-medium">
                        {fnStats.duration}
                      </span>
                    </span>
                    <span>•</span>
                    <span>
                      Error Rate:{" "}
                      <span className="text-slate-300 font-medium">
                        {fnStats.error}
                      </span>
                    </span>
                    <span>•</span>
                    <span>
                      Memory:{" "}
                      <span className="text-slate-300 font-medium">
                        {fnStats.memory}
                      </span>
                    </span>
                  </div>
                )}
              </div>

              {/* Close button */}
              <button
                onClick={onClose}
                className="shrink-0 grid place-items-center w-8 h-8 rounded-lg
                           bg-white/5 border border-white/10 text-slate-400
                           hover:text-white hover:bg-white/10 transition-colors"
              >
                <CloseRoundedIcon fontSize="small" />
              </button>
            </div>
          </div>

          {/* ── Body (scrollable) ── */}
          <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
            {/* Stats Row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                {
                  label: "Total Alerts",
                  value: total,
                  color: "text-slate-200",
                },
                {
                  label: "Open",
                  value: openCount,
                  color: "text-emerald-400",
                },
                {
                  label: "Critical",
                  value: critCount,
                  color: "text-red-400",
                },
                {
                  label: "Warnings",
                  value: warnCount,
                  color: "text-orange-400",
                },
              ].map(({ label, value, color }) => (
                <div
                  key={label}
                  className="rounded-xl border border-white/10 bg-white/[0.03] p-3 text-center"
                >
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">
                    {label}
                  </div>
                  <div className={`text-xl font-bold ${color}`}>{value}</div>
                </div>
              ))}
            </div>

            {/* Severity Breakdown */}
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 space-y-3">
              <h3 className="text-sm font-semibold text-slate-300 mb-2">
                Severity Distribution
              </h3>
              <SeverityBar label="CRITICAL" count={critCount} total={total} />
              <SeverityBar label="WARNING" count={warnCount} total={total} />
              <SeverityBar label="INFO" count={infoCount} total={total} />
            </div>

            {/* Related Alerts Table */}
            <div className="rounded-xl border border-white/10 bg-white/[0.03] overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/10">
                <h3 className="text-sm font-semibold text-slate-300">
                  Related Alerts
                </h3>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider">
                  {total} alert{total !== 1 ? "s" : ""} • Click to expand
                </span>
              </div>

              {alerts.length === 0 ? (
                <div className="px-4 py-8 text-center text-sm text-slate-500">
                  No alerts for this function.
                </div>
              ) : (
                <div className="max-h-[340px] overflow-y-auto">
                  {alerts.map((alert) => (
                    <AlertRow key={alert.id} alert={alert} />
                  ))}
                </div>
              )}
            </div>

            {/* Recent Logs */}
            <div className="rounded-xl border border-white/10 bg-white/[0.03] overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/10">
                <h3 className="text-sm font-semibold text-slate-300">
                  Recent Logs
                </h3>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider">
                  {logs.length} log{logs.length !== 1 ? "s" : ""}
                </span>
              </div>

              {logs.length === 0 ? (
                <div className="px-4 py-8 text-center text-sm text-slate-500">
                  No logs for this function.
                </div>
              ) : (
                <div className="max-h-[260px] overflow-y-auto">
                  <table className="w-full text-sm text-left">
                    <thead className="text-slate-500 text-xs sticky top-0 bg-[#0b1530]">
                      <tr>
                        <th className="py-2 px-4">Timestamp</th>
                        <th className="py-2 px-4">Event</th>
                        <th className="py-2 px-4">IP Address</th>
                        <th className="py-2 px-4">Status</th>
                        <th className="py-2 px-4">Duration</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logs.map((log, i) => (
                        <tr
                          key={i}
                          className="border-t border-white/5 hover:bg-white/[0.02] transition-colors"
                        >
                          <td className="py-2.5 px-4 text-slate-400 text-xs">
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td className="py-2.5 px-4 text-slate-300">
                            {log.event}
                          </td>
                          <td className="py-2.5 px-4 text-slate-400">
                            {log.ip_address}
                          </td>
                          <td className="py-2.5 px-4">
                            <span
                              className={`px-2 py-0.5 rounded-full text-xs ${
                                log.status === "success"
                                  ? "bg-green-500/20 text-green-400"
                                  : log.status === "blocked"
                                  ? "bg-yellow-500/20 text-yellow-400"
                                  : "bg-red-500/20 text-red-400"
                              }`}
                            >
                              {log.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-slate-300">
                            {log.duration}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* ── Footer ── */}
          <div className="shrink-0 border-t border-white/10 bg-[#0a1328]/90 backdrop-blur px-6 py-4 flex items-center justify-between">
            <span className="text-xs text-slate-500">
              {total} alert{total !== 1 ? "s" : ""} linked • {openCount} open
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  onClose();
                  navigate("/alerts");
                }}
                className="flex items-center gap-1.5 px-4 py-2 text-xs rounded-lg
                           bg-white/5 border border-white/10 text-slate-300
                           hover:bg-white/10 hover:text-white transition-colors"
              >
                <OpenInNewRoundedIcon style={{ fontSize: 14 }} />
                View All Alerts
              </button>
              <button
                onClick={onClose}
                className="px-4 py-2 text-xs rounded-lg bg-blue-600/20 border
                           border-blue-500/40 text-blue-300 hover:bg-blue-600/30
                           transition-colors font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
