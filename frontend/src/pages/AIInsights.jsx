import { useEffect, useState, useCallback, useMemo } from "react";
import axios from "axios";
import InsightStatCard from "../components/InsightStatCard";
import InsightCard from "../components/InsightCard";


const POLL_INTERVAL = 5000;


// ── Generate insights from real alert data ──────────────────────────────
function buildInsights(alerts) {
  if (!alerts.length) return [];

  const insights = [];
  const now = Date.now();

  // Group alerts by threat type
  const byThreat = {};
  for (const a of alerts) {
    const type = a.threat_type || "Unknown";
    if (!byThreat[type]) byThreat[type] = [];
    byThreat[type].push(a);
  }

  // Group alerts by function
  const byFunction = {};
  for (const a of alerts) {
    const fn = a.function || "unknown";
    if (!byFunction[fn]) byFunction[fn] = [];
    byFunction[fn].push(a);
  }

  // Insight 1: Most common threat type
  const sortedThreats = Object.entries(byThreat).sort((a, b) => b[1].length - a[1].length);
  if (sortedThreats.length > 0) {
    const [topThreat, topAlerts] = sortedThreats[0];
    const avgConf = topAlerts.reduce((s, a) => s + (a.confidence || a.anomaly_score || 0), 0) / topAlerts.length;
    const critCount = topAlerts.filter((a) => a.severity === "CRITICAL").length;
    const latest = topAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
    const ago = timeAgo(latest.timestamp, now);

    insights.push({
      id: "threat-top",
      title: `${topThreat} — Primary Threat Detected`,
      level: critCount > 0 ? "high" : "medium",
      description: `${topAlerts.length} alerts classified as ${topThreat}. ${critCount} are CRITICAL severity. Most targeted function: ${getMostCommon(topAlerts, "function")}.`,
      confidence: Math.round(avgConf * 100 * 10) / 10,
      action: critCount > 0 ? `${critCount} blocked` : "Monitoring active",
      time: ago,
    });
  }

  // Insight 2: Critical alerts spike
  const criticals = alerts.filter((a) => a.severity === "CRITICAL" && a.status === "OPEN");
  if (criticals.length > 0) {
    const avgScore = criticals.reduce((s, a) => s + (a.anomaly_score || 0), 0) / criticals.length;
    const latest = criticals.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
    const functions = [...new Set(criticals.map((a) => a.function))];

    insights.push({
      id: "critical-spike",
      title: `${criticals.length} Critical Alerts — Immediate Attention Required`,
      level: "high",
      description: `${criticals.length} OPEN critical alerts detected across ${functions.length} function(s): ${functions.slice(0, 3).join(", ")}${functions.length > 3 ? "..." : ""}. Average anomaly score: ${(avgScore * 100).toFixed(1)}%.`,
      confidence: Math.round(avgScore * 100 * 10) / 10,
      action: "Investigation recommended",
      time: timeAgo(latest.timestamp, now),
    });
  }

  // Insight 3: Most affected function
  const sortedFunctions = Object.entries(byFunction).sort((a, b) => b[1].length - a[1].length);
  if (sortedFunctions.length > 0) {
    const [topFn, fnAlerts] = sortedFunctions[0];
    const errorRate = fnAlerts.filter((a) => a.severity === "CRITICAL" || a.severity === "WARNING").length / fnAlerts.length;
    const latest = fnAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

    insights.push({
      id: "function-risk",
      title: `${topFn} — Highest Risk Function`,
      level: errorRate > 0.5 ? "high" : "medium",
      description: `${fnAlerts.length} total alerts on ${topFn}. ${(errorRate * 100).toFixed(0)}% are WARNING or CRITICAL. Threat types: ${[...new Set(fnAlerts.map((a) => a.threat_type || "Unknown"))].join(", ")}.`,
      confidence: Math.round(errorRate * 100 * 10) / 10,
      action: errorRate > 0.5 ? "Review function security" : "Continue monitoring",
      time: timeAgo(latest.timestamp, now),
    });
  }

  // Insight 4: Layer 2 scan summary (if any alerts have layer2_report)
  const l2Alerts = alerts.filter((a) => a.layer2_report);
  if (l2Alerts.length > 0) {
    const patternCounts = {};
    for (const a of l2Alerts) {
      const patterns = a.layer2_report?.patterns?.matched_patterns || [];
      for (const p of patterns) {
        const name = p.name || p.attack_type || "Unknown";
        patternCounts[name] = (patternCounts[name] || 0) + 1;
      }
    }
    const topPatterns = Object.entries(patternCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);
    const avgRisk = l2Alerts.reduce((s, a) => s + (a.layer2_report?.risk?.adjusted_score || 0), 0) / l2Alerts.length;
    const latest = l2Alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

    insights.push({
      id: "l2-summary",
      title: "Layer 2 Deep Scan Summary",
      level: avgRisk > 0.6 ? "high" : "info",
      description: `${l2Alerts.length} packets underwent deep analysis. Top patterns: ${topPatterns.map(([n, c]) => `${n} (${c})`).join(", ") || "None"}. Average risk score: ${(avgRisk * 100).toFixed(1)}%.`,
      confidence: Math.round(avgRisk * 100 * 10) / 10,
      action: `${l2Alerts.filter((a) => a.layer2_report?.decision === "BLOCK").length} blocked by L2`,
      time: timeAgo(latest.timestamp, now),
    });
  }

  // Insight 5: Open vs closed ratio
  const openCount = alerts.filter((a) => a.status === "OPEN").length;
  const closedCount = alerts.filter((a) => a.status === "CLOSED").length;
  if (alerts.length > 0) {
    const openPct = (openCount / alerts.length) * 100;
    insights.push({
      id: "resolution-rate",
      title: `Alert Resolution Rate — ${(100 - openPct).toFixed(0)}%`,
      level: openPct > 70 ? "high" : openPct > 40 ? "medium" : "info",
      description: `${openCount} alerts remain OPEN, ${closedCount} have been CLOSED. ${openPct > 70 ? "High number of unresolved alerts requires attention." : openPct > 40 ? "Moderate backlog of open alerts." : "Good resolution rate."}`,
      confidence: Math.round((100 - openPct) * 10) / 10,
      action: openPct > 50 ? "Review open alerts" : "On track",
      time: "Current",
    });
  }

  return insights;
}


// ── Helpers ─────────────────────────────────────────────────────────────
function timeAgo(ts, now) {
  const diff = now - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function getMostCommon(alerts, field) {
  const counts = {};
  for (const a of alerts) {
    const val = a[field] || "unknown";
    counts[val] = (counts[val] || 0) + 1;
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || "unknown";
}


// =========================================================================
// COMPONENT
// =========================================================================

export default function AIInsights() {
  const [modelHealth, setModelHealth] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAll = useCallback(async () => {
    try {
      const [healthRes, alertsRes] = await Promise.all([
        axios.get("/api/model/health"),
        axios.get("/api/alerts?limit=1000"),
      ]);
      setModelHealth(healthRes.data);
      setAlerts(Array.isArray(alertsRes.data) ? alertsRes.data : []);
      setError(null);
    } catch (err) {
      console.error("AI Insights fetch error:", err);
      setError("Backend unavailable — please ensure the server is running");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchAll]);

  // ── Computed stats ────────────────────────────────────────────────
  const accuracy = modelHealth?.accuracy ?? 0;
  const trainingActive = modelHealth?.trainingActive ?? false;
  const sarimaProgress = modelHealth?.sarima_progress ?? 0;
  const totalThreats = alerts.filter(
    (a) => a.severity === "CRITICAL" || a.severity === "WARNING"
  ).length;

  // False positive estimate: INFO alerts that were auto-closed
  const infoAlerts = alerts.filter((a) => a.severity === "INFO").length;
  const falsePositiveRate = alerts.length > 0
    ? ((infoAlerts / alerts.length) * 100).toFixed(1)
    : "0.0";

  // ── Build insights from real data ─────────────────────────────────
  const insights = useMemo(() => buildInsights(alerts), [alerts]);

  return (
    <div className="space-y-8 text-white">

      {/* HEADER */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">AI Insights</h1>
          <p className="text-slate-400 mt-1">
            AI-generated security intelligence and performance insights
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`h-2.5 w-2.5 rounded-full ${
              error ? "bg-red-400" : "bg-emerald-400 animate-pulse"
            }`}
          />
          <span className="text-xs text-slate-400">
            {error ? "Disconnected" : "Live"}
          </span>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* TOP STATS — from backend */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <InsightStatCard
          title="Model Accuracy"
          value={`${accuracy.toFixed(1)}%`}
          subtext={modelHealth?.delta ? `+${modelHealth.delta.toFixed(1)}% ↑` : "—"}
          color="green"
        />
        <InsightStatCard
          title="Threats Detected"
          value={totalThreats.toLocaleString()}
          subtext={`of ${alerts.length} total alerts`}
          color="blue"
        />
        <InsightStatCard
          title="False Positives"
          value={`${falsePositiveRate}%`}
          subtext={`${infoAlerts} INFO-level alerts`}
          color="yellow"
        />
        <InsightStatCard
          title="AI Training"
          value={trainingActive ? "Learning" : "Active"}
          subtext={
            trainingActive
              ? `SARIMA: ${sarimaProgress.toFixed(0)}%`
              : "Detection mode"
          }
          color="purple"
        />
      </div>

      {/* INSIGHTS LIST — generated from real alerts */}
      <div className="space-y-4">
        {loading ? (
          <div className="text-slate-400 py-8 text-center">Loading insights…</div>
        ) : insights.length === 0 ? (
          <div className="rounded-xl bg-white/5 border border-white/10 p-8 text-center">
            <p className="text-slate-400">No insights yet — send packets to generate alerts</p>
          </div>
        ) : (
          insights.map((insight) => (
            <InsightCard key={insight.id} insight={insight} />
          ))
        )}
      </div>
    </div>
  );
}