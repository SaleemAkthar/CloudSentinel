import { useState } from "react";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import ExpandLessRoundedIcon from "@mui/icons-material/ExpandLessRounded";
import OpenInNewRoundedIcon from "@mui/icons-material/OpenInNewRounded";
import { useNavigate } from "react-router-dom";

// ── Severity colour map ─────────────────────────────────────────────────
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

const LEVEL_COLORS = {
  high: {
    badge: "border-red-500 text-red-400 bg-red-500/15",
    glow: "shadow-red-500/20",
  },
  medium: {
    badge: "border-yellow-400 text-yellow-300 bg-yellow-400/15",
    glow: "shadow-yellow-400/20",
  },
  low: {
    badge: "border-blue-400 text-blue-300 bg-blue-400/15",
    glow: "shadow-blue-400/20",
  },
  info: {
    badge: "border-purple-400 text-purple-300 bg-purple-400/15",
    glow: "shadow-purple-400/20",
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────
function formatTime(ts) {
  return new Date(ts).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function SeverityBar({ label, count, total, sev }) {
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
              { label: "Anomaly Score", value: `${((alert.anomaly_score || 0) * 100).toFixed(1)}%` },
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
        </div>
      )}
    </div>
  );
}

// =========================================================================
// MAIN MODAL
// =========================================================================
export default function InsightDetailModal({ insight, onClose }) {
  const navigate = useNavigate();
  const alerts = insight._alerts || [];
  const total = alerts.length;

  const critCount = alerts.filter((a) => a.severity === "CRITICAL").length;
  const warnCount = alerts.filter((a) => a.severity === "WARNING").length;
  const infoCount = alerts.filter((a) => a.severity === "INFO").length;
  const openCount = alerts.filter((a) => a.status === "OPEN").length;

  const level = LEVEL_COLORS[insight.level] || LEVEL_COLORS.info;

  return (
    <>
      {/* CSS keyframes injected inline */}
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
          {/* ────── Header ────── */}
          <div className="shrink-0 border-b border-white/10 bg-[#0a1328]/90 backdrop-blur px-6 py-5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                {/* Title + Badge */}
                <div className="flex items-center gap-3 flex-wrap mb-2">
                  <h2 className="text-lg font-bold text-white truncate">
                    {insight.title}
                  </h2>
                  <span
                    className={`text-xs px-2.5 py-1 rounded-full border font-semibold ${level.badge}`}
                  >
                    {insight.level}
                  </span>
                </div>

                {/* Description */}
                <p className="text-sm text-slate-400 leading-relaxed">
                  {insight.description}
                </p>

                {/* Meta Row */}
                <div className="flex items-center gap-4 mt-3 text-xs text-slate-500">
                  <span>
                    Action:{" "}
                    <span className="text-slate-300 font-medium">
                      {insight.action}
                    </span>
                  </span>
                  <span>•</span>
                  <span>{insight.time}</span>
                </div>
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

            {/* Confidence Bar */}
            <div className="mt-4">
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="text-slate-400">Confidence</span>
                <span className="text-white font-semibold">
                  {insight.confidence}%
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-white/5 ring-1 ring-white/10 overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-700"
                  style={{ width: `${insight.confidence}%` }}
                />
              </div>
            </div>
          </div>

          {/* ────── Body (scrollable) ────── */}
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
              <SeverityBar
                label="CRITICAL"
                count={critCount}
                total={total}
              />
              <SeverityBar
                label="WARNING"
                count={warnCount}
                total={total}
              />
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
                  No individual alerts are linked to this insight.
                </div>
              ) : (
                <div className="max-h-[340px] overflow-y-auto">
                  {alerts
                    .slice()
                    .sort(
                      (a, b) =>
                        new Date(b.timestamp) - new Date(a.timestamp)
                    )
                    .map((alert) => (
                      <AlertRow key={alert.id} alert={alert} />
                    ))}
                </div>
              )}
            </div>
          </div>

          {/* ────── Footer ────── */}
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
