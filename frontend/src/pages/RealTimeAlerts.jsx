import { useEffect, useState } from "react";
import AlertItem from "../components/AlertItem";
import Investigation from "./Investigate";
import alertsData from "../test/alerts.json";

export default function RealTimeAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState(null);

  useEffect(() => {
    try {
      console.log("Alert data:", alertsData);
      setAlerts(Array.isArray(alertsData) ? alertsData : []);
      setError(null);
      setLoading(false);
    } catch (err) {
      console.error("Error loading alerts:", err);
      setError(err.message);
      setAlerts([]);
      setLoading(false);
    }
  }, []);

  console.log("Current alerts state:", alerts);
  const critical = alerts.filter(a => a.severity === "CRITICAL").length;
  const high = alerts.filter(a => a.severity === "WARNING").length;
  const medium = alerts.filter(a => a.severity === "INFO").length;

  console.log("Summary - Critical:", critical, "High:", high, "Medium:", medium, "Total:", alerts.length);

  return (
    <div className="space-y-8">
      {/* HEADER */}
      <div>
        <h1 className="text-3xl font-bold text-white">
          Real-Time Security Alerts
        </h1>
        <p className="text-slate-400 mt-1">
          Monitor and respond to security threats in real-time
        </p>
      </div>

      {/* SUMMARY CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <SummaryCard title="Critical" count={critical} color="red" />
        <SummaryCard title="High" count={high} color="orange" />
        <SummaryCard title="Medium" count={medium} color="yellow" />
        <SummaryCard title="Total" count={alerts.length} color="blue" />
      </div>

      {/* ACTIVE THREATS SECTION */}
      <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
        <div className="px-5 py-3 border-b border-white/10 text-sm font-semibold text-slate-300">
          Active Threats
        </div>

        {error && (
          <div className="p-6 text-red-400">Error: {error}</div>
        )}
        
        {loading ? (
          <div className="p-6 text-slate-400">Loading alerts…</div>
        ) : alerts.length === 0 ? (
          <div className="p-6 text-emerald-400">No active threats 🎉</div>
        ) : (
          <div className="divide-y divide-white/10">
            {alerts.map(alert => (
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
