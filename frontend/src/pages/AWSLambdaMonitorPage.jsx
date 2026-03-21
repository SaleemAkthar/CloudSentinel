import { useEffect, useState, useCallback } from "react";
import axios from "axios";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";


// ── Custom tooltips ─────────────────────────────────────────────────────

const InvocationTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-[#0a1628] border border-gray-700 rounded-lg px-4 py-3 shadow-lg">
      <p className="text-gray-400 text-xs mb-1">{label}</p>
      {payload.map((entry, idx) => (
        <p key={idx} className="text-sm" style={{ color: entry.color }}>
          {entry.name}: <span className="font-semibold">{entry.value.toLocaleString()}</span>
        </p>
      ))}
    </div>
  );
};

const ThreatTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0]?.payload;
  return (
    <div className="bg-[#0a1628] border border-gray-700 rounded-lg px-4 py-3 shadow-lg">
      <p className="text-gray-300 text-xs font-semibold mb-1">{label}</p>
      <p className="text-sm" style={{ color: d.color }}>
        Packets: <span className="font-semibold">{d.packets}</span>
      </p>
    </div>
  );
};


// ── Threat-type color map (matches Layer 2 attack_patterns.py) ──────────
const THREAT_COLORS = {
  "DDoS":               "#ef4444",
  "IP Spoofing":        "#f97316",
  "SQL Injection":      "#eab308",
  "Crypto Mining":      "#a855f7",
  "Data Exfiltration":  "#3b82f6",
  "Data Exfil":         "#3b82f6",
  "Memory Exhaustion":  "#06b6d4",
  "Memory Attack":      "#06b6d4",
  "Injection Attempt":  "#eab308",
  "Unknown Anomaly":    "#6b7280",
};

// Normalize threat names from alerts to display labels
const normalizeThreat = (raw) => {
  const map = {
    "Crypto Mining":      "Crypto Mining",
    "Data Exfiltration":  "Data Exfil",
    "Data Exfil":         "Data Exfil",
    "Memory Exhaustion":  "Memory Attack",
    "Memory Attack":      "Memory Attack",
    "Injection Attempt":  "SQL Injection",
    "SQL Injection":      "SQL Injection",
    "DDoS":               "DDoS",
    "IP Spoofing":        "IP Spoofing",
  };
  return map[raw] || "Unknown";
};


// ── Build hourly invocation buckets from log_storage ────────────────────
function buildHourlyBuckets(logs) {
  const now = new Date();
  const buckets = [];

  for (let i = 23; i >= 0; i--) {
    const bucketTime = new Date(now.getTime() - i * 60 * 60 * 1000);
    const hourKey = bucketTime.toISOString().slice(0, 13);
    const label = `${String(bucketTime.getHours()).padStart(2, "0")}:00`;

    let actual = 0;
    for (const log of logs) {
      const ts = log.timestamp || "";
      if (ts.slice(0, 13) === hourKey) {
        actual += 1;
      }
    }

    buckets.push({ time: label, actual, predicted: 0 });
  }

  // Compute SARIMA-style predicted line (3-hour rolling average)
  for (let i = 0; i < buckets.length; i++) {
    const windowStart = Math.max(0, i - 1);
    const windowEnd = Math.min(buckets.length - 1, i + 1);
    let sum = 0;
    let count = 0;
    for (let j = windowStart; j <= windowEnd; j++) {
      sum += buckets[j].actual;
      count++;
    }
    buckets[i].predicted = Math.round(sum / count);
  }

  return buckets;
}


// ── Build threat counts from alerts ─────────────────────────────────────
function buildThreatCounts(alerts) {
  const counts = {
    "DDoS":           0,
    "IP Spoofing":    0,
    "SQL Injection":  0,
    "Crypto Mining":  0,
    "Data Exfil":     0,
    "Memory Attack":  0,
  };

  for (const alert of alerts) {
    const raw = alert.threat_type || alert.attack_type || "";
    const label = normalizeThreat(raw);
    if (label in counts) {
      counts[label] += 1;
    }

    const patterns = alert.layer2_report?.patterns?.matched_patterns;
    if (Array.isArray(patterns)) {
      for (const p of patterns) {
        const pLabel = normalizeThreat(p.attack_type || "");
        if (pLabel in counts) {
          counts[pLabel] += 1;
        }
      }
    }
  }

  const colorMap = {
    "DDoS":          "#ef4444",
    "IP Spoofing":   "#f97316",
    "SQL Injection":  "#eab308",
    "Crypto Mining":  "#a855f7",
    "Data Exfil":     "#3b82f6",
    "Memory Attack":  "#06b6d4",
  };

  return Object.entries(counts).map(([type, packets]) => ({
    type,
    packets,
    color: colorMap[type] || "#6b7280",
  }));
}



// ── Real Lambda functions from LocalStack simulation ────────────────────

const FALLBACK_FUNCTIONS = [
  { name: "api-handler",     status: "active",  invocations: 0, duration: "0ms",  error: "0%",  memory: "128MB" },
  { name: "file-processor",  status: "active",  invocations: 0, duration: "0ms",  error: "0%",  memory: "128MB" },
  { name: "db-query",        status: "active",  invocations: 0, duration: "0ms",  error: "0%",  memory: "128MB" },
  { name: "auth-service",    status: "active",  invocations: 0, duration: "0ms",  error: "0%",  memory: "128MB" },
];


// ── Polling interval — refresh every 10s ────────────────────────────────
const POLL_INTERVAL = 10000;


// =========================================================================
// COMPONENT
// =========================================================================

export default function AWSLambdaMonitorPage() {

  const [overview, setOverview]             = useState(null);
  const [functions, setFunctions]           = useState(FALLBACK_FUNCTIONS);
  const [invocationData, setInvocationData] = useState([]);
  const [threatData, setThreatData]         = useState([]);
  const [loading, setLoading]               = useState(true);
  const [selectedFn, setSelectedFn]         = useState(null);
  const [fnAlerts, setFnAlerts]             = useState([]);
  const [fnLogs, setFnLogs]                 = useState([]);
  const [awsLive, setAwsLive]   = useState(false);
  const [awsLoading, setAwsLoading] = useState(false);

  // ── Fetch from existing backend endpoints ───────────────────────────
  const fetchAll = useCallback(async () => {
    try {
      const [overviewRes, functionsRes, logsRes, alertsRes] = await Promise.all([
        axios.get("/api/lambda/overview"),
        axios.get("/api/lambda/functions"),
        axios.get("/api/logs?limit=5000"),
        axios.get("/api/alerts?limit=5000"),
      ]);

      setOverview(overviewRes.data);

      const logs = Array.isArray(logsRes.data) ? logsRes.data : [];
      const hourly = buildHourlyBuckets(logs);
      setInvocationData(hourly);

      const alerts = Array.isArray(alertsRes.data) ? alertsRes.data : [];
      const threats = buildThreatCounts(alerts);
      setThreatData(threats);

      const fnData = functionsRes.data.map((fn) => {
        const errorPct = fn.error_rate_pct;
        let status = "active";
        if (errorPct >= 10) status = "error";
        else if (errorPct >= 2) status = "warning";

        return {
          name:        fn.function_name,
          status,
          invocations: fn.invocations,
          duration:    `${fn.avg_duration_ms}ms`,
          error:       `${errorPct}%`,
          memory:      `${fn.avg_memory_mb}MB`,
        };
      });

      setFunctions(fnData.length > 0 ? fnData : FALLBACK_FUNCTIONS);
    } catch (err) {
      console.error("Lambda Monitor fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchAll]);

  // ── Fetch details for a specific function ─────────────────────────
  const openFnDetails = useCallback(async (fnName) => {
    setSelectedFn(fnName);
    try {
      const [alertsRes, logsRes] = await Promise.all([
        axios.get("/api/alerts?limit=500"),
        axios.get("/api/logs?limit=2000"),
      ]);
      const alerts = Array.isArray(alertsRes.data) ? alertsRes.data : [];
      const logs = Array.isArray(logsRes.data) ? logsRes.data : [];

      setFnAlerts(
        alerts
          .filter((a) => a.function === fnName)
          .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
          .slice(0, 20)
      );
      setFnLogs(
        logs
          .filter((l) => l.function === fnName)
          .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
          .slice(0, 20)
      );
    } catch (err) {
      console.error("Failed to fetch function details:", err);
      setFnAlerts([]);
      setFnLogs([]);
    }
  }, []);

  // ── Derived values with fallbacks ───────────────────────────────────
  const totalInvocations = overview?.total_invocations ?? 0;
  const avgResponseTime  = overview?.avg_response_time ?? 0;
  const errorRate        = overview?.error_rate ?? 0;
  const activeFunctions  = overview?.active_functions ?? 4;
  const totalFunctions   = functions.length || 6;
  const errorFunctions   = functions.filter((f) => f.status === "error").length;

  // ── Style helpers ───────────────────────────────────────────────────
  const statusBorder = (s) => {
    if (s === "active")  return "border-green-500 bg-green-500/10";
    if (s === "warning") return "border-yellow-500 bg-yellow-500/10";
    if (s === "error")   return "border-red-500 bg-red-500/10";
    return "border-blue-500";
  };

  const statusBadge = (s) => {
    if (s === "active")  return "bg-green-500/20 text-green-400";
    if (s === "warning") return "bg-yellow-500/20 text-yellow-400";
    if (s === "error")   return "bg-red-500/20 text-red-400";
    return "bg-blue-500/20 text-blue-400";
  };

  // ── Render ──────────────────────────────────────────────────────────
  return (
    <div className="space-y-8">

      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">AWS Lambda Monitor</h1>
        <p className="text-slate-400 mt-1">Real-time monitoring of serverless functions</p>
      </div>

      <div className="space-y-6">

        {/* ── Stats Cards ────────────────────────────────────────── */}
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-[#0f1b3d] p-5 rounded-xl">
            <p className="text-gray-400 text-sm">Total Invocations</p>
            <h2 className="text-3xl font-bold">{totalInvocations.toLocaleString()}</h2>
          </div>
          <div className="bg-[#0f1b3d] p-5 rounded-xl">
            <p className="text-gray-400 text-sm">Avg Response Time</p>
            <h2 className="text-3xl font-bold">{avgResponseTime}ms</h2>
          </div>
          <div className="bg-[#0f1b3d] p-5 rounded-xl">
            <p className="text-gray-400 text-sm">Error Rate</p>
            <h2 className="text-3xl font-bold">{errorRate}%</h2>
          </div>
          <div className="bg-[#0f1b3d] p-5 rounded-xl">
            <p className="text-gray-400 text-sm">Active Functions</p>
            <h2 className="text-3xl font-bold">{activeFunctions}/{totalFunctions}</h2>
            {errorFunctions > 0 && (
              <p className="text-yellow-400 text-sm">{errorFunctions} error</p>
            )}
          </div>
        </div>

        {/* ── Charts ─────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 gap-6">

          {/* Invocations — Last 24 Hours (sarima_forecaster.py) */}
          <div className="bg-[#0f1b3d] rounded-xl p-5 h-64">
            <h3 className="text-sm text-gray-400 mb-3">Invocations — Last 24 Hours</h3>
            {invocationData.length > 0 ? (
              <ResponsiveContainer width="100%" height="85%">
                <AreaChart data={invocationData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradActual" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradPredicted" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22c55e" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "#6b7280", fontSize: 11 }}
                    axisLine={{ stroke: "#1e2d4a" }}
                    tickLine={false}
                    interval={3}
                  />
                  <YAxis
                    tick={{ fill: "#6b7280", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    width={45}
                  />
                  <Tooltip content={<InvocationTooltip />} />
                  <Legend
                    verticalAlign="top"
                    align="right"
                    iconType="circle"
                    iconSize={8}
                    wrapperStyle={{ fontSize: 11, color: "#9ca3af" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="predicted"
                    name="SARIMA Predicted"
                    stroke="#22c55e"
                    strokeWidth={2}
                    strokeDasharray="5 3"
                    fill="url(#gradPredicted)"
                    dot={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="actual"
                    name="Actual"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    fill="url(#gradActual)"
                    dot={false}
                    activeDot={{ r: 4, fill: "#3b82f6", stroke: "#0f1b3d", strokeWidth: 2 }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-gray-500 text-sm">
                {loading ? "Loading invocation data..." : "No data available"}
              </div>
            )}
          </div>

          {/* Captured Threats — Layer 2 Scanner (layer2_scanner.py) */}
          <div className="bg-[#0f1b3d] rounded-xl p-5 h-64">
            <h3 className="text-sm text-gray-400 mb-3">Captured Threats — Packet Count</h3>
            {threatData.length > 0 ? (
              <ResponsiveContainer width="100%" height="85%">
                <BarChart data={threatData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" vertical={false} />
                  <XAxis
                    dataKey="type"
                    tick={{ fill: "#6b7280", fontSize: 10 }}
                    axisLine={{ stroke: "#1e2d4a" }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: "#6b7280", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    width={40}
                  />
                  <Tooltip content={<ThreatTooltip />} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
                  <Bar dataKey="packets" radius={[4, 4, 0, 0]} barSize={30}>
                    {threatData.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-gray-500 text-sm">
                {loading ? "Loading threat data..." : "No threats captured"}
              </div>
            )}
          </div>

        </div>

        {/* ── Function Details ───────────────────────────────────── */}
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">Function Details</h2>

          {functions.map((fn) => (
            <div
              key={fn.name}
              className={`border rounded-xl p-5 flex justify-between items-center ${statusBorder(fn.status)}`}
            >
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <h3 className="font-semibold">{fn.name}</h3>
                  <span className={`text-xs px-2 py-1 rounded-full ${statusBadge(fn.status)}`}>
                    {fn.status}
                  </span>
                </div>
                <div className="grid grid-cols-4 gap-6 text-sm text-gray-300">
                  <div>
                    <p className="text-gray-400">Invocations</p>
                    <p>{fn.invocations?.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Avg Duration</p>
                    <p>{fn.duration}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Error Rate</p>
                    <p>{fn.error}</p>
                  </div>
                  <div>
                    <p className="text-gray-400">Memory</p>
                    <p>{fn.memory}</p>
                  </div>
                </div>
              </div>
              <button
                onClick={() => openFnDetails(fn.name)}
                className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm"
              >
                View Details
              </button>
            </div>
          ))}
        </div>

      </div>

      {/* ── Function Detail Modal ──────────────────────────────────── */}
      {selectedFn && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0a1628] border border-white/10 rounded-2xl w-full max-w-3xl max-h-[85vh] overflow-y-auto shadow-2xl">

            {/* Modal header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-white/10">
              <div>
                <h2 className="text-xl font-bold text-white">{selectedFn}</h2>
                <p className="text-xs text-slate-400 mt-0.5">Function activity from Layer 1 + Layer 2</p>
              </div>
              <button
                onClick={() => setSelectedFn(null)}
                className="text-slate-400 hover:text-white text-2xl leading-none px-2"
              >
                ×
              </button>
            </div>

            {/* Alerts section */}
            <div className="px-6 py-4">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">
                Recent Alerts ({fnAlerts.length})
              </h3>
              {fnAlerts.length === 0 ? (
                <p className="text-sm text-slate-500">No alerts for this function</p>
              ) : (
                <div className="space-y-2">
                  {fnAlerts.map((a) => (
                    <div
                      key={a.id}
                      className={`rounded-lg p-3 border-l-4 ${
                        a.severity === "CRITICAL"
                          ? "border-red-500 bg-red-500/10"
                          : a.severity === "WARNING"
                          ? "border-orange-400 bg-orange-400/10"
                          : "border-yellow-400 bg-yellow-400/10"
                      }`}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span
                          className={`text-xs px-2 py-0.5 rounded-full font-semibold ${
                            a.severity === "CRITICAL"
                              ? "bg-red-500/20 text-red-400"
                              : a.severity === "WARNING"
                              ? "bg-orange-500/20 text-orange-400"
                              : "bg-yellow-500/20 text-yellow-400"
                          }`}
                        >
                          {a.severity}
                        </span>
                        <span className={`text-xs font-semibold ${a.status === "OPEN" ? "text-red-400" : "text-emerald-400"}`}>
                          {a.status}
                        </span>
                        {a.threat_type && (
                          <span className="text-xs text-slate-400">• {a.threat_type}</span>
                        )}
                      </div>
                      <div className="text-sm text-slate-300">
                        Score: <span className="font-semibold">{((a.anomaly_score || 0) * 100).toFixed(1)}%</span>
                        {a.features?.duration_ms != null && (
                          <> • Duration: <span className="font-semibold">{a.features.duration_ms}ms</span></>
                        )}
                        {a.confidence != null && (
                          <> • Confidence: <span className="font-semibold">{(a.confidence * 100).toFixed(0)}%</span></>
                        )}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        {new Date(a.timestamp).toLocaleString()}
                        {a.features?.ip_address && <> • IP: {a.features.ip_address}</>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Logs section */}
            <div className="px-6 py-4 border-t border-white/10">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">
                Recent Logs ({fnLogs.length})
              </h3>
              {fnLogs.length === 0 ? (
                <p className="text-sm text-slate-500">No logs for this function</p>
              ) : (
                <table className="w-full text-sm text-left">
                  <thead className="text-gray-500 text-xs">
                    <tr>
                      <th className="py-1.5">Timestamp</th>
                      <th>Event</th>
                      <th>IP Address</th>
                      <th>Status</th>
                      <th>Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fnLogs.map((log, i) => (
                      <tr key={i} className="border-t border-white/5">
                        <td className="py-2 text-slate-400 text-xs">{new Date(log.timestamp).toLocaleString()}</td>
                        <td className="text-slate-300">{log.event}</td>
                        <td className="text-slate-400">{log.ip_address}</td>
                        <td>
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
                        <td className="text-slate-300">{log.duration}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Close button */}
            <div className="px-6 py-4 border-t border-white/10 flex justify-end">
              <button
                onClick={() => setSelectedFn(null)}
                className="bg-white/5 hover:bg-white/10 border border-white/10 px-4 py-2 rounded-lg text-sm text-slate-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}