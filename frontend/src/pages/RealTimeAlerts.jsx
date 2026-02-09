import { useEffect, useState } from "react";
import { getAlerts } from "../services/api";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import ErrorOutlineRoundedIcon from "@mui/icons-material/ErrorOutlineRounded";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";

export default function RealTimeAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        setLoading(true);
        const data = await getAlerts();
        setAlerts(data);
      } catch (error) {
        console.error("Failed to fetch alerts:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchAlerts();
    
    // Refresh every 5 seconds
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case "high":
        return "bg-red-500/10 border-red-500/30 text-red-400";
      case "medium":
        return "bg-yellow-500/10 border-yellow-500/30 text-yellow-400";
      case "low":
        return "bg-blue-500/10 border-blue-500/30 text-blue-400";
      default:
        return "bg-slate-500/10 border-slate-500/30 text-slate-400";
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity?.toLowerCase()) {
      case "high":
        return <ErrorOutlineRoundedIcon className="text-red-400" />;
      case "medium":
        return <WarningAmberRoundedIcon className="text-yellow-400" />;
      default:
        return <InfoOutlinedIcon className="text-blue-400" />;
    }
  };

  return (
    <div className="w-full">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-white">Real-Time Alerts</h1>
        <p className="mt-2 text-slate-400">
          Live anomaly detection and security alerts
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-slate-400">Loading alerts...</div>
        </div>
      ) : alerts.length === 0 ? (
        <div className="rounded-xl bg-white/5 border border-white/10 p-8 text-center">
          <div className="text-slate-400">No alerts at the moment</div>
          <p className="mt-2 text-sm text-slate-500">
            Your system is running smoothly!
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              className={`rounded-xl border p-4 transition-all hover:shadow-lg ${getSeverityColor(
                alert.severity
              )}`}
            >
              <div className="flex items-start gap-4">
                <div className="mt-1">{getSeverityIcon(alert.severity)}</div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-4">
                    <h3 className="text-lg font-semibold">{alert.message}</h3>
                    <span className="text-xs whitespace-nowrap opacity-70">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <p className="mt-2 text-sm opacity-90">{alert.details}</p>

                  <div className="mt-3 flex items-center gap-2">
                    <span className="inline-block px-2 py-1 rounded text-xs bg-white/10">
                      {alert.type?.replace(/_/g, " ")}
                    </span>
                    <span className="inline-block px-2 py-1 rounded text-xs bg-white/10 capitalize">
                      {alert.severity}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
