import { useState, useEffect } from "react";
import axios from "axios";
import { allowAlert, blockAlert } from "../services/api";
import GlassCard from "../components/GlassCard";
import StatusDot from "../components/StatusDot";

export default function Investigation({ alertId, onClose }) {
  const [alert, setAlert] = useState(null);
  const [l2Report, setL2Report] = useState(null);
  const [loadingAlert, setLoadingAlert] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [error, setError] = useState(null);

  // Allow / Block action state
  const [actionLoading, setActionLoading] = useState(null); // null | 'allow' | 'block'
  const [actionError, setActionError] = useState(null);
  const [actionDone, setActionDone] = useState(null);       // null | 'ALLOWED' | 'BLOCKED'

  // Fetch the real alert from backend
  useEffect(() => {
    if (!alertId) return;
    setLoadingAlert(true);
    axios.get(`/api/alerts/${alertId}`)
      .then(r => {
        setAlert(r.data);
        // If already resolved, show the badge immediately
        if (r.data.resolution) {
          setActionDone(r.data.resolution);
        }
        // If already investigated, show cached report
        if (r.data.layer2_report) {
          setL2Report(r.data.layer2_report);
        }
      })
      .catch(() => setError("Failed to load alert data."))
      .finally(() => setLoadingAlert(false));
  }, [alertId]);

  const runInvestigation = async () => {
    setInvestigating(true);
    setError(null);
    try {
      const r = await axios.post(`/api/alerts/${alertId}/investigate`);
      setL2Report(r.data.report);
      // Update alert severity/decision from L2 result
      if (alert) {
        setAlert(prev => ({
          ...prev,
          severity: r.data.severity || prev.severity,
          decision: r.data.decision || prev.decision,
        }));
      }
    } catch (err) {
      setError(
        err.response?.data?.detail || "Investigation failed. No packet data stored."
      );
    } finally {
      setInvestigating(false);
    }
  };

  // Handle Allow / Block analyst decision
  const handleDecision = async (type) => {
    setActionLoading(type);
    setActionError(null);
    try {
      if (type === 'allow') {
        await allowAlert(alertId);
        setActionDone('ALLOWED');
      } else {
        await blockAlert(alertId);
        setActionDone('BLOCKED');
      }
      // Auto-close the modal after 2 seconds
      setTimeout(() => onClose(), 2000);
    } catch (err) {
      setActionError(
        err.response?.data?.detail || `Failed to ${type} alert. Please try again.`
      );
    } finally {
      setActionLoading(null);
    }
  };

  if (loadingAlert) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur">
        <div className="bg-[#0a1328] rounded-2xl p-8 text-slate-300">Loading alert…</div>
      </div>
    );
  }

  if (!alert) return null;

  const runtime = alert.features || {};
  const timeStr = new Date(alert.timestamp).toLocaleString();
  const tone = alert.severity === "CRITICAL" ? "err"
    : alert.severity === "WARNING" ? "warn" : "ok";

  // Layer 2 data
  const ip = l2Report?.ip;
  const pkt = l2Report?.packet;
  const patterns = l2Report?.patterns;
  const topology = l2Report?.topology;
  const risk = l2Report?.risk;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur">
      <div className="bg-[#0a1328] rounded-2xl w-[92%] max-w-4xl max-h-[88vh] flex flex-col
                      shadow-xl border border-white/10 overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-white/10
                        sticky top-0 bg-[#0a1328]/95 z-10">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold text-white truncate">
              {alert.function} — {alert.severity} Alert
            </h2>
            <span className="text-xs text-slate-400">{alert.id}</span>
            <StatusDot tone={tone} />
          </div>
          <button onClick={onClose}
            className="px-3 py-1 text-xs rounded-lg bg-white/5 border border-white/10
                       text-slate-300 hover:bg-white/10">
            Close
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4">

          {/* Error banner */}
          {error && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10
                            px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          )}

          {/* Alert Metadata */}
          <GlassCard title="Alert Metadata">
            <div className="grid grid-cols-2 gap-2 text-sm text-slate-300">
              <div><span className="text-white font-semibold">ID:</span> {alert.id}</div>
              <div><span className="text-white font-semibold">Function:</span> {alert.function}</div>
              <div><span className="text-white font-semibold">Severity:</span> {alert.severity}</div>
              <div><span className="text-white font-semibold">Status:</span> {alert.status}</div>
              <div><span className="text-white font-semibold">Score:</span> {((alert.anomaly_score || 0) * 100).toFixed(1)}%</div>
              <div><span className="text-white font-semibold">Time:</span> {timeStr}</div>
              {alert.threat_type && (
                <div><span className="text-white font-semibold">Threat:</span> {alert.threat_type}</div>
              )}
              {alert.decision && (
                <div><span className="text-white font-semibold">Decision:</span> {alert.decision}</div>
              )}
            </div>
          </GlassCard>

          {/* Runtime Data */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <GlassCard title="Runtime Data">
              <div className="space-y-1 text-sm text-slate-300">
                <div><span className="text-white font-semibold">Duration:</span> {runtime.duration_ms || 0}ms</div>
                <div><span className="text-white font-semibold">Memory:</span> {runtime.memory_used_mb || 0}MB</div>
                <div><span className="text-white font-semibold">API Calls:</span> {runtime.outbound_calls || 0}</div>
                <div><span className="text-white font-semibold">Destinations:</span> {runtime.unique_destinations || 0}</div>
                <div><span className="text-white font-semibold">Errors:</span> {runtime.error_count || 0}</div>
                <div><span className="text-white font-semibold">IP:</span> {runtime.ip_address || "—"}</div>
                <div><span className="text-white font-semibold">TTL:</span> {runtime.ttl || "—"}</div>
              </div>
            </GlassCard>

            {/* IP Analysis — only after L2 */}
            {ip ? (
              <GlassCard title="IP Analysis">
                <div className="space-y-1 text-sm text-slate-300">
                  <div><span className="text-white font-semibold">Country:</span> {ip.geolocation?.country_name || "—"}</div>
                  <div><span className="text-white font-semibold">ASN:</span> {ip.asn?.asn || "—"} ({ip.asn?.organisation || "—"})</div>
                  <div><span className="text-white font-semibold">Reputation:</span>{" "}
                    <span className={
                      ip.reputation?.label === "MALICIOUS" ? "text-red-400" :
                        ip.reputation?.label === "SUSPICIOUS" ? "text-orange-400" : "text-emerald-400"
                    }>
                      {ip.reputation?.label || "—"}
                    </span>
                  </div>
                  <div><span className="text-white font-semibold">Spoofing Score:</span> {((ip.spoofing?.spoofing_score || 0) * 100).toFixed(0)}%</div>
                  {ip.reputation?.flags?.length > 0 && (
                    <div className="mt-2">
                      {ip.reputation.flags.map((f, i) => (
                        <div key={i} className="text-xs text-orange-300">• {f}</div>
                      ))}
                    </div>
                  )}
                </div>
              </GlassCard>
            ) : (
              <GlassCard title="IP Analysis">
                <div className="text-sm text-slate-400 italic">
                  Run investigation to see IP analysis
                </div>
              </GlassCard>
            )}
          </div>

          {/* Attack Patterns — only after L2 */}
          {patterns ? (
            <GlassCard title={`Attack Patterns (${patterns.threat_count || 0} matched)`}>
              {patterns.threat_count === 0 ? (
                <div className="text-sm text-emerald-400">No attack patterns matched</div>
              ) : (
                <div className="space-y-3">
                  {patterns.matched_patterns?.map((p, i) => (
                    <div key={i} className="rounded-lg border border-white/10 bg-white/5 p-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-semibold text-white">{p.name}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${p.confidence >= 0.7 ? "bg-red-500/20 text-red-400" :
                            p.confidence >= 0.4 ? "bg-orange-500/20 text-orange-400" :
                              "bg-yellow-500/20 text-yellow-400"
                          }`}>
                          {(p.confidence * 100).toFixed(0)}% confidence
                        </span>
                      </div>
                      {p.indicators?.slice(0, 3).map((ind, j) => (
                        <div key={j} className="text-xs text-slate-400">• {ind}</div>
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </GlassCard>
          ) : null}

          {/* Risk Score — only after L2 */}
          {risk ? (
            <GlassCard title="Risk Assessment">
              <div className="grid grid-cols-2 gap-3 text-sm text-slate-300">
                <div><span className="text-white font-semibold">Risk Score:</span> {((risk.adjusted_score || 0) * 100).toFixed(1)}%</div>
                <div><span className="text-white font-semibold">Confidence:</span> {((risk.confidence || 0) * 100).toFixed(1)}%</div>
                <div><span className="text-white font-semibold">Severity:</span> {risk.severity || "—"}</div>
                <div><span className="text-white font-semibold">Action:</span>{" "}
                  <span className={risk.recommendation?.action === "BLOCK" ? "text-red-400" : "text-orange-400"}>
                    {risk.recommendation?.action || "—"}
                  </span>
                </div>
              </div>
              {risk.recommendation?.reasoning?.length > 0 && (
                <div className="mt-3 space-y-1">
                  <div className="text-xs font-semibold text-slate-300">Reasoning:</div>
                  {risk.recommendation.reasoning.map((r, i) => (
                    <div key={i} className="text-xs text-slate-400">• {r}</div>
                  ))}
                </div>
              )}
              {risk.recommendation?.mitigations?.length > 0 && (
                <div className="mt-3 space-y-1">
                  <div className="text-xs font-semibold text-orange-300">Recommended Actions:</div>
                  {risk.recommendation.mitigations.map((m, i) => (
                    <div key={i} className="text-xs text-orange-200">→ {m}</div>
                  ))}
                </div>
              )}
            </GlassCard>
          ) : null}

          {/* Topology — only after L2 */}
          {topology ? (
            <GlassCard title="Network Topology">
              <div className="grid grid-cols-2 gap-2 text-sm text-slate-300">
                <div><span className="text-white font-semibold">Topology Risk:</span> {((topology.risk_score || 0) * 100).toFixed(0)}%</div>
                <div><span className="text-white font-semibold">Hops:</span> {topology.hop_analysis?.inferred_hops || "—"}</div>
                <div><span className="text-white font-semibold">Transit:</span> {topology.transit?.provider_name || "—"}</div>
                <div><span className="text-white font-semibold">Transit Risk:</span> {topology.transit?.risk_level || "—"}</div>
              </div>
              {topology.anomalies?.anomalies?.length > 0 && (
                <div className="mt-2 space-y-1">
                  {topology.anomalies.anomalies.map((a, i) => (
                    <div key={i} className="text-xs text-orange-300">⚠ {a}</div>
                  ))}
                </div>
              )}
            </GlassCard>
          ) : null}

          {/* Packet Analysis — only after L2 */}
          {pkt ? (
            <GlassCard title="Packet Analysis">
              <div className="grid grid-cols-2 gap-2 text-sm text-slate-300">
                <div><span className="text-white font-semibold">Packet Risk:</span> {((pkt.risk_score || 0) * 100).toFixed(0)}%</div>
                <div><span className="text-white font-semibold">Exfil Score:</span> {((pkt.exfiltration?.exfiltration_score || 0) * 100).toFixed(0)}%</div>
                <div><span className="text-white font-semibold">Size In:</span> {pkt.size?.bytes_in || 0} bytes</div>
                <div><span className="text-white font-semibold">Size Out:</span> {pkt.size?.bytes_out || 0} bytes</div>
                <div><span className="text-white font-semibold">Fragments:</span> {pkt.fragmentation?.effective_fragments || 0}</div>
                <div><span className="text-white font-semibold">Latency:</span> {pkt.latency?.total_ms || 0}ms</div>
              </div>
            </GlassCard>
          ) : null}

        </div>

        {/* Footer — Investigate / Allow / Block buttons */}
        <div className="flex justify-between items-center p-4 border-t border-white/10 gap-3">
          <div className="flex-1">
            {/* Action error banner */}
            {actionError && (
              <div className="text-red-400 text-xs bg-red-500/10 px-3 py-2 rounded-lg border border-red-500/20">
                {actionError}
              </div>
            )}
            {/* Success banner */}
            {actionDone && (
              <div className={`text-xs px-3 py-2 rounded-lg font-semibold ${
                actionDone === 'ALLOWED'
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                  : 'bg-red-500/15 text-red-400 border border-red-500/30'
              }`}>
                {actionDone === 'ALLOWED' ? '✓ Marked as Allowed — closing…' : '⛔ IP Blocked — closing…'}
              </div>
            )}
            {!actionError && !actionDone && (
              <span className="text-xs text-slate-500">
                {l2Report
                  ? `Layer 2 scan completed in ${l2Report.elapsed_ms}ms`
                  : "Layer 2 analysis not yet run"}
              </span>
            )}
          </div>

          <div className="flex gap-2 shrink-0">
            {!l2Report && !actionDone && (
              <button
                onClick={runInvestigation}
                disabled={investigating}
                className="px-4 py-2 text-sm rounded-lg bg-blue-600/20 border border-blue-500
                           text-blue-300 hover:bg-blue-600/30 disabled:opacity-50"
              >
                {investigating ? "Investigating…" : "🔍 Run Layer 2 Investigation"}
              </button>
            )}

            {/* Resolved badge — shown if already actioned */}
            {actionDone ? (
              <span className={`px-4 py-2 text-sm rounded-lg font-semibold ${
                actionDone === 'ALLOWED'
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                  : 'bg-red-500/15 text-red-400 border border-red-500/30'
              }`}>
                {actionDone === 'ALLOWED' ? '✓ ALLOWED' : '⛔ BLOCKED'}
              </span>
            ) : (
              <>
                <button
                  onClick={() => handleDecision('allow')}
                  disabled={!!actionLoading}
                  className="px-4 py-2 text-sm rounded-lg bg-emerald-600/20 border border-emerald-500
                             text-emerald-400 hover:bg-emerald-600/30 disabled:opacity-50"
                >
                  {actionLoading === 'allow' ? 'Allowing…' : '✓ Allow'}
                </button>
                <button
                  onClick={() => handleDecision('block')}
                  disabled={!!actionLoading}
                  className="px-4 py-2 text-sm rounded-lg bg-red-600/20 border border-red-500
                             text-red-400 hover:bg-red-600/30 disabled:opacity-50"
                >
                  {actionLoading === 'block' ? 'Blocking…' : '⛔ Block IP'}
                </button>
              </>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}