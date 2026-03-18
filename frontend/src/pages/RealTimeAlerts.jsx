import { useEffect, useState, useCallback } from "react";
import axios from "axios";
import AlertItem from "../components/AlertItem";
import Investigation from "./Investigate";
import alertsData from "../test/alerts.json";


// ── Polling interval — refresh every 0.5 seconds ────────────────────────
const POLL_INTERVAL = 500; // 0.5 seconds


export default function RealTimeAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [isLive, setIsLive] = useState(false);

  // ── Fetch alerts from live backend ──────────────────────────────────
  const fetchAlerts = useCallback(async () => {
    try {
      const res = await axios.get("/api/alerts?limit=500");
      const data = Array.isArray(res.data) ? res.data : [];

      if (data.length > 0) {
        // Sort by timestamp descending (newest first)
        data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        setAlerts(data);
        setIsLive(true);
      } else {
        // Backend has no alerts yet — fall back to static JSON
        setAlerts(
          Array.isArray(alertsData)
            ? alertsData.slice().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            : []
        );
        setIsLive(false);
      }
      setError(null);
    } catch (err) {
      console.error("Failed to fetch alerts:", err);
      // On error, fall back to static JSON so page isn't blank
      if (alerts.length === 0) {
        setAlerts(
          Array.isArray(alertsData)
            ? alertsData.slice().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            : []
        );
        setIsLive(false);
      }
      setError("Backend unavailable — showing cached alerts");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  // ── Counts ──────────────────────────────────────────────────────────
  const critical = alerts.filter((a) => a.severity === "CRITICAL").length;
  const high = alerts.filter((a) => a.severity === "WARNING").length;
  const medium = alerts.filter((a) => a.severity === "INFO").length;

  return (
    <div className="space-y-8">
      {/* HEADER */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">
            Real-Time Security Alerts
          </h1>
          <p className="text-slate-400 mt-1">
            Monitor and respond to security threats in real-time
          </p>
        </div>

        {/* Live / Cached indicator */}
        <div className="flex items-center gap-2">
          <span
            className={`h-2.5 w-2.5 rounded-full ${
              isLive ? "bg-emerald-400 animate-pulse" : "bg-yellow-400"
            }`}
          />
          <span className="text-xs text-slate-400">
            {isLive ? "Live — Layer 2 Scanner" : "Cached data"}
          </span>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-300">
          {error}
        </div>
      )}

      {/* SUMMARY CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <SummaryCard title="Critical" count={critical} color="red" />
        <SummaryCard title="High" count={high} color="orange" />
        <SummaryCard title="Medium" count={medium} color="yellow" />
        <SummaryCard title="Total" count={alerts.length} color="blue" />
      </div>

      {/* ACTIVE THREATS */}
      <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
        <div className="px-5 py-3 border-b border-white/10 text-sm font-semibold text-slate-300 flex items-center justify-between">
          <span>Active Threats</span>
          <span className="text-xs text-slate-500 font-normal">
            Polling every {POLL_INTERVAL / 1000}s
          </span>
        </div>

        {loading ? (
          <div className="p-6 text-slate-400">Loading alerts…</div>
        ) : alerts.length === 0 ? (
          <div className="p-6 text-emerald-400">No active threats 🎉</div>
        ) : (
          <div className="divide-y divide-white/10">
            {alerts.map((alert) => (
              <AlertItem
                key={alert.id}
                alert={alert}
                onInvestigate={(alertId) => setSelectedAlertId(alertId)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Investigation Modal */}
      {selectedAlertId && (
        <Investigation
          alertId={selectedAlertId}
          onClose={() => setSelectedAlertId(null)}
        />
      )}
    </div>
  );
}


function SummaryCard({ title, count, color }) {
  const colors = {
    red: "text-red-400 bg-red-500/10 border-red-500/30",
    orange: "text-orange-300 bg-orange-400/10 border-orange-400/30",
    yellow: "text-yellow-300 bg-yellow-400/10 border-yellow-400/30",
    blue: "text-blue-300 bg-blue-400/10 border-blue-400/30",
  };

  return (
    <div className={`rounded-2xl border p-4 ${colors[color]}`}>
      <div className="text-sm uppercase tracking-wide">{title}</div>
      <div className="mt-2 text-3xl font-bold">{count}</div>
      <div className="text-xs mt-1 opacity-80">Alerts</div>
    </div>
  );
}