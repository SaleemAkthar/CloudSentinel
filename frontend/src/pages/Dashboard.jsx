import { useEffect, useMemo, useState } from "react";
import GlassCard from "../components/GlassCard";
import StatusDot from "../components/StatusDot";
import MetricBar from "../components/MetricBar";
import { getAlerts, getModelHealth } from "../services/api";

import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import ShowChartRoundedIcon from "@mui/icons-material/ShowChartRounded";
import AutoAwesomeRoundedIcon from "@mui/icons-material/AutoAwesomeRounded";

import {
  AreaChart,
  Area,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from "recharts";

// --- helpers ---
function hourLabel(date) {
  const h = String(date.getHours()).padStart(2, "0");
  return `${h}:00`;
}

function bucket24h(alerts) {
  // build 24 hourly buckets based on latest timestamp day
  const maxTs = alerts.length ? Math.max(...alerts.map(a => +new Date(a.timestamp))) : Date.now();
  const end = new Date(maxTs);
  const start = new Date(end);
  start.setHours(end.getHours() - 23, 0, 0, 0);

  const buckets = [];
  for (let i = 0; i < 24; i++) {
    const d = new Date(start);
    d.setHours(start.getHours() + i);
    buckets.push({
      key: +d,
      time: hourLabel(d),
      threats: 0,
      anomalies: 0,
      _count: 0,
    });
  }

  for (const a of alerts) {
    const t = new Date(a.timestamp);
    if (t < start || t > end) continue;
    const idx = Math.floor((t - start) / (60 * 60 * 1000));
    if (idx < 0 || idx > 23) continue;

    // threats: OPEN + (CRITICAL/WARNING) count
    if (a.status === "OPEN" && (a.severity === "CRITICAL" || a.severity === "WARNING")) {
      buckets[idx].threats += 1;
    }

    // anomalies: avg anomaly_score
    buckets[idx].anomalies += typeof a.anomaly_score === "number" ? a.anomaly_score : 0;
    buckets[idx]._count += 1;
  }

  return buckets.map(b => ({
    time: b.time,
    threats: b.threats,
    anomalies: b._count ? +(b.anomalies / b._count).toFixed(2) : 0,
  }));
}

function classifyFunctionStatus(latestAlert) {
  if (!latestAlert) return { text: "Idle", tone: "idle" };
  if (latestAlert.severity === "CRITICAL" && latestAlert.status === "OPEN") return { text: "Error", tone: "err" };
  if (latestAlert.severity === "WARNING" && latestAlert.status === "OPEN") return { text: "Warning", tone: "warn" };
  return { text: "Active", tone: "ok" };
}

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    getAlerts().then(setAlerts);
    getModelHealth().then(setHealth);
  }, []);

  const stats = useMemo(() => {
    const open = alerts.filter(a => a.status === "OPEN");
    const critical = open.filter(a => a.severity === "CRITICAL").length;

    // High: WARNING with anomaly_score >= 0.70
    // Medium: WARNING with anomaly_score < 0.70
    const high = open.filter(a => a.severity === "WARNING" && a.anomaly_score >= 0.7).length;
    const medium = open.filter(a => a.severity === "WARNING" && a.anomaly_score < 0.7).length;

    return { critical, high, medium };
  }, [alerts]);

  const functions = useMemo(() => {
    // latest alert per function
    const byFn = new Map();
    for (const a of alerts) {
      const prev = byFn.get(a.function);
      if (!prev || +new Date(a.timestamp) > +new Date(prev.timestamp)) byFn.set(a.function, a);
    }
    const items = Array.from(byFn.entries()).map(([fn, latest]) => ({
      name: fn,
      latest,
      ...classifyFunctionStatus(latest),
    }));

    // active count = ok or warn
    const activeCount = items.filter(i => i.tone === "ok" || i.tone === "warn").length;

    return { items, activeCount, total: items.length };
  }, [alerts]);

  const chartData = useMemo(() => bucket24h(alerts), [alerts]);

  const model = health || { accuracy: 0, precision: 0, recall: 0, trainingActive: false, delta: 0 };

  return (
    <div className="space-y-6">
      {/* top cards */}
      <div className="grid gap-5 lg:grid-cols-3">
        {/* Real-time alerts */}
        <GlassCard
          title="Real-Time Alerts"
          icon={<WarningAmberRoundedIcon fontSize="small" />}
          right={<WarningAmberRoundedIcon fontSize="small" />}
          className="bg-gradient-to-b from-white/5 to-white/0"
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded-xl border border-red-500/100 bg-red-500/30 px-4 py-4">
              <div>
                <div className="text-sm font-semibold text-slate-100">Critical</div>
                <div className="text-xs text-red-200/80">Active threats</div>
              </div>
              <div className="text-2xl font-semibold text-red-200">{stats.critical}</div>
            </div>

            <div className="flex items-center justify-between rounded-xl border border-orange-500/100 bg-orange-500/30 px-4 py-4">
              <div>
                <div className="text-sm font-semibold text-slate-100">High</div>
                <div className="text-xs text-orange-200/80">Active threats</div>
              </div>
              <div className="text-2xl font-semibold text-orange-200">{stats.high}</div>
            </div>

            <div className="flex items-center justify-between rounded-xl border border-yellow-500/100 bg-yellow-500/30 px-4 py-4">
              <div>
                <div className="text-sm font-semibold text-slate-100">Medium</div>
                <div className="text-xs text-yellow-200/80">Active threats</div>
              </div>
              <div className="text-2xl font-semibold text-yellow-200">{stats.medium}</div>
            </div>

            <div className="pt-2 text-xs text-emerald-300">
              need to add comparison with previous period
            </div>
          </div>
        </GlassCard>

        {/* Lambda functions */}
        <GlassCard
          title="Lambda Functions"
          icon={<ShowChartRoundedIcon fontSize="small" />}
          right={<ShowChartRoundedIcon fontSize="small" />}
          className="bg-gradient-to-b from-white/5 to-white/0"
        >
          <div className="space-y-4">
            <div className="flex items-end gap-2">
              <div className="text-3xl font-semibold text-slate-100">{functions.activeCount}</div>
              <div className="pb-1 text-sm text-slate-300">/ {functions.total} Active</div>
            </div>

            <div className="h-2 w-full rounded-full bg-white/5 ring-1 ring-white/10 overflow-hidden">
              <div
                className="h-full bg-sky-400"
                style={{ width: `${functions.total ? (functions.activeCount / functions.total) * 100 : 0}%` }}
              />
            </div>

            <div className="space-y-2 pt-1">
              {functions.items.slice(0, 5).map((f) => (
                <div key={f.name} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2 text-slate-200">
                    <StatusDot tone={f.tone} />
                    <span className="text-slate-200">{f.name}</span>
                  </div>
                  <div
                    className={
                      f.tone === "ok"
                        ? "text-emerald-300"
                        : f.tone === "warn"
                        ? "text-yellow-300"
                        : f.tone === "err"
                        ? "text-red-300"
                        : "text-slate-400"
                    }
                  >
                    {f.text}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </GlassCard>

        {/* AI Model Health */}
        <GlassCard
          title="AI Model Health"
          icon={<AutoAwesomeRoundedIcon fontSize="small" />}
          right={<AutoAwesomeRoundedIcon fontSize="small" />}
          className="bg-gradient-to-b from-white/5 to-white/0"
        >
          <div className="space-y-4">
            <div className="flex items-end justify-between">
              <div>
                <div className="text-4xl font-semibold text-slate-100">{model.accuracy.toFixed(1)}%</div>
                <div className="mt-1 text-xs text-slate-300">Overall Model Accuracy</div>
              </div>
              <div className="pb-2 text-sm text-emerald-300">↗ +{model.delta.toFixed(1)}%</div>
            </div>

            <MetricBar label="Accuracy" value={model.accuracy} />
            <MetricBar label="Precision" value={model.precision} />
            <MetricBar label="Recall" value={model.recall} />

            <div className="pt-2 text-sm text-slate-200 flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${model.trainingActive ? "bg-emerald-400" : "bg-slate-400"}`} />
              <span className="text-emerald-300">
                Model Training: {model.trainingActive ? "Active" : "Paused"}
              </span>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* Big chart */}
      <GlassCard
        title="Risk Summary - Last 24 Hours"
        right={<div className="text-xs text-emerald-300">comparing to the yesterday</div>}
        className="p-0 overflow-hidden"
      >
        <div className="px-5 pt-5 pb-2">
          <div className="flex items-center justify-between">
            
            <div className="text-xs text-slate-300">Threats • Anomalies</div>
          </div>
        </div>

        <div className="h-[340px] px-2 pb-4">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 8, right: 18, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="gAnom" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22D3EE" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#22D3EE" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
              <XAxis dataKey="time" stroke="rgba(255,255,255,0.55)" tick={{ fontSize: 12 }} />
              <YAxis stroke="rgba(255,255,255,0.55)" tick={{ fontSize: 12 }} />
              <Tooltip
                contentStyle={{
                  background: "rgba(10, 20, 45, 0.95)",
                  border: "1px solid rgba(255,255,255,0.12)",
                  borderRadius: 12,
                  color: "white",
                }}
              />
              <Legend />

              <Area
                type="monotone"
                dataKey="threats"
                name="Threats"
                stroke="#3B82F6"
                fill="url(#gThreats)"
                strokeWidth={2}
                dot={false}
              />
              <Area
                type="monotone"
                dataKey="anomalies"
                name="Anomalies"
                stroke="#22D3EE"
                fill="url(#gAnom)"
                strokeWidth={2}
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </GlassCard>
    </div>
  );
}
