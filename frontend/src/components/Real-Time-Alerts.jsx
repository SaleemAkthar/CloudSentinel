// React hooks for state management and lifecycle
import { useEffect, useState } from "react";

// API function to fetch alerts (mock or backend)
import { getAlerts } from "../services/api";

/*
  Styles for each alert severity.
  These control border color, background glow, and text color.
*/
const severityStyles = {
  critical: "border-red-500 bg-red-500/10 text-red-400",
  high: "border-orange-400 bg-orange-400/10 text-orange-300",
  medium: "border-yellow-400 bg-yellow-400/10 text-yellow-300",
};

export default function RealTimeAlerts() {
  // Holds list of alert objects
  const [alerts, setAlerts] = useState([]);

  // Loading state for UX feedback
  const [loading, setLoading] = useState(true);

  /*
    useEffect runs once when the component loads.
    This simulates "real-time" fetching for now.
  */
  useEffect(() => {
    async function loadAlerts() {
      // Fetch alerts from API (mock JSON or backend)
      const data = await getAlerts();

      // Store alerts in state
      setAlerts(data);

      // Stop loading spinner
      setLoading(false);
    }

    loadAlerts();
  }, []);

  return (
    <div className="space-y-6">
      {/* ===== PAGE HEADER ===== */}
      <div>
        <h1 className="text-3xl font-bold text-white">
          Real-Time Alerts
        </h1>
        <p className="mt-1 text-slate-400">
          Live security events detected by Cloud Sentinel
        </p>
      </div>

      {/* ===== SUMMARY CARDS ===== */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Count alerts by severity */}
        <SummaryCard
          title="Critical"
          count={count(alerts, "critical")}
          color="red"
        />
        <SummaryCard
          title="High"
          count={count(alerts, "high")}
          color="orange"
        />
        <SummaryCard
          title="Medium"
          count={count(alerts, "medium")}
          color="yellow"
        />
      </div>

      {/* ===== ALERT LIST CONTAINER ===== */}
      <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
        {/* List Header */}
        <div className="px-5 py-3 border-b border-white/10 text-sm font-semibold text-slate-300">
          Active Threats
        </div>

        {/* Loading state */}
        {loading ? (
          <div className="p-6 text-slate-400">
            Loading alerts…
          </div>

        /* No alerts found */
        ) : alerts.length === 0 ? (
          <div className="p-6 text-emerald-400">
            No active threats 🎉
          </div>

        /* Render alert list */
        ) : (
          <ul className="divide-y divide-white/10">
            {alerts.map((alert) => (
              <li
                key={alert.id}
                className={`p-4 border-l-4 ${
                  severityStyles[alert.severity]
                }`}
              >
                <div className="flex justify-between items-start">
                  
                  {/* Alert text content */}
                  <div>
                    <div className="font-semibold text-white">
                      {alert.message}
                    </div>

                    <div className="text-sm text-slate-400 mt-1">
                      {alert.details}
                    </div>

                    <div className="text-xs text-slate-500 mt-2">
                      {new Date(alert.timestamp).toLocaleString()}
                    </div>
                  </div>

                  {/* Severity badge */}
                  <span
                    className={`text-xs px-2 py-1 rounded-full border ${
                      severityStyles[alert.severity]
                    }`}
                  >
                    {alert.severity.toUpperCase()}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

/* ================= HELPERS ================= */

/*
  Counts number of alerts for a given severity
  Used by summary cards
*/
function count(alerts, level) {
  return alerts.filter((a) => a.severity === level).length;
}

/*
  Reusable summary card component
  Displays severity + count
*/
function SummaryCard({ title, count, color }) {
  // Color presets
  const colors = {
    red: "text-red-400 bg-red-500/10 border-red-500/30",
    orange: "text-orange-300 bg-orange-400/10 border-orange-400/30",
    yellow: "text-yellow-300 bg-yellow-400/10 border-yellow-400/30",
  };

  return (
    <div
      className={`rounded-2xl border p-4 ${colors[color]}`}
    >
      <div className="text-sm uppercase tracking-wide">
        {title}
      </div>

      <div className="mt-2 text-3xl font-bold">
        {count}
      </div>

      <div className="text-xs mt-1 opacity-80">
        Active threats
      </div>
    </div>
  );
}
