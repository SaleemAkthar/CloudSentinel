import { useEffect, useMemo, useState } from "react";
import GlassCard from "../components/GlassCard";
import { getAlerts } from "../services/api";

import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";

/* ================= HELPERS ================= */

function countBySeverity(alerts, level) {
  return alerts.filter(
    (a) => a.severity === level && a.status === "OPEN"
  ).length;
}

function severityTone(severity) {
  switch (severity) {
    case "CRITICAL":
      return "border-red-500 bg-red-500/10 text-red-400";
    case "WARNING":
      return "border-orange-400 bg-orange-400/10 text-orange-300";
    case "INFO":
      return "border-yellow-400 bg-yellow-400/10 text-yellow-300";
    default:
      return "border-slate-500 bg-slate-500/10 text-slate-300";
  }
}

function statusTone(status) {
  switch (status) {
    case "OPEN":
      return "text-red-400";
    case "MITIGATING":
      return "text-yellow-400";
    case "RESOLVED":
      return "text-emerald-400";
    default:
      return "text-slate-400";
  }
}

/* ================= COMPONENT ================= */

export default function RealTimeAlerts() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    getAlerts().then(setAlerts);
  }, []);

  const stats = useMemo(() => {
    return {
      critical: countBySeverity(alerts, "CRITICAL"),
      high: alerts.filter(
        (a) =>
          a.severity === "WARNING" &&
          a.anomaly_score >= 0.7 &&
          a.status === "OPEN"
      ).length,
      medium: alerts.filter(
        (a) =>
          a.severity === "WARNING" &&
          a.anomaly_score < 0.7 &&
          a.status === "OPEN"
      ).length,
      total: alerts.length,
    };
  }, [alerts]);

  return (
    <div className="space-y-6">
      {/* ===== PAGE HEADER ===== */}
      <div>
        <h1 className="text-3xl font-bold text-white">
          Real-Time Security Alerts
        </h1>
        <p className="mt-1 text-slate-400">
          Monitor and respond to security threats in real-time
        </p>
      </div>

      {/* ===== SUMMARY CARDS ===== */}
      <div className="grid gap-5 md:grid-cols-4">
        <SummaryCard title="Critical" value={stats.critical} color="red" />
        <SummaryCard title="High" value={stats.high} color="orange" />
        <SummaryCard title="Medium" value={stats.medium} color="yellow" />
        <SummaryCard title="Total Today" value={stats.total} color="blue" />
      </div>

      {/* ===== ACTIVE ALERTS LIST ===== */}
      <GlassCard
        title="Active Alerts"
        icon={<WarningAmberRoundedIcon fontSize="small" />}
        className="bg-gradient-to-b from-white/5 to-white/0"
      >
        <div className="divide-y divide-white/10">
          {alerts.length === 0 ? (
            <div className="py-8 text-center text-emerald-400">
              No active threats 🎉
            </div>
          ) : (
            alerts.map((alert) => (
              <div
                key={alert.id}
                className={`py-5 px-2 border-l-4 ${severityTone(
                  alert.severity
                )}`}
              >
                <div className="flex justify-between items-start gap-6">
                  {/* LEFT */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-3">
                      <h3 className="font-semibold text-slate-100">
                        {alert.message}
                      </h3>

                      <span
                        className={`text-xs px-2 py-1 rounded-full border ${severityTone(
                          alert.severity
                        )}`}
                      >
                        {alert.severity}
                      </span>

                      <span
                        className={`text-xs font-semibold ${statusTone(
                          alert.status
                        )}`}
                      >
                        {alert.status}
                      </span>
                    </div>

                    <p className="text-sm text-slate-400">
                      {alert.details}
                    </p>

                    <div className="text-xs text-slate-500">
                      Target: {alert.function} • Source: {alert.source_ip} •{" "}
                      {new Date(alert.timestamp).toLocaleString()}
                    </div>
                  </div>

                  {/* RIGHT ACTIONS */}
                  <div className="flex gap-2">
                    <button className="px-4 py-2 text-sm rounded-lg border border-sky-500 text-sky-400 hover:bg-sky-500/10 transition">
                      Investigate
                    </button>

                    <button className="px-4 py-2 text-sm rounded-lg border border-red-500 text-red-400 hover:bg-red-500/10 transition">
                      Block
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </GlassCard>
    </div>
  );
}

/* ================= REUSABLE SUMMARY CARD ================= */

function SummaryCard({ title, value, color }) {
  const colors = {
    red: "border-red-500/30 bg-red-500/10 text-red-300",
    orange: "border-orange-500/30 bg-orange-500/10 text-orange-300",
    yellow: "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
    blue: "border-blue-500/30 bg-blue-500/10 text-blue-300",
  };

  return (
    <div
      className={`rounded-2xl border p-5 ${colors[color]} backdrop-blur`}
    >
      <div className="text-sm uppercase tracking-wide">
        {title}
      </div>

      <div className="mt-3 text-3xl font-semibold">
        {value}
      </div>

      <div className="text-xs opacity-80 mt-1">
        Active threats
      </div>
    </div>
  );
}
